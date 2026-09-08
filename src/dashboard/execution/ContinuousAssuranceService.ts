import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest, PlanPreviewResponse, ComparisonResult } from "../types/DashboardTypes.js";
import { continuousAssurancePolicyInputSchema, type ContinuousAssurancePolicyInput } from "../contracts/ContinuousAssuranceSchemas.js";
import type { ProviderAdapterService } from "./ProviderAdapterService.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import type { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import type { EvidenceGovernanceService } from "./EvidenceGovernanceService.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";

type TriggerType = "MANUAL" | "SCHEDULE" | "DEPLOYMENT";
type RunState = "LAUNCHING" | "RUNNING" | "COMPLETED" | "FAILED" | "BLOCKED" | "CANCELLED";

interface ExecutionPort { preview(request: DashboardScanCreateRequest): Promise<PlanPreviewResponse>; enqueue(request: DashboardScanCreateRequest): Promise<string>; }
interface AdapterPort {
  materialize(id: string): { target: { id: string; rowVersion: number }; input: { targetId: string }; binding: { profileId: string; versionId: string; adapterDigest: string } };
  materializeScanRequest(id: string): DashboardScanCreateRequest;
  assertExecutionBinding(request: DashboardScanCreateRequest): Promise<void>;
  bindScan(scanId: string, binding: { profileId: string; versionId: string; adapterDigest: string }): void;
}
interface ComparisonPort { compare(oldScanId: string, newScanId: string, options?: { createdByUserId?: string }): ComparisonResult; }
interface EvidencePort { available(): boolean; createExport(scanIds: readonly string[], actor: string): Record<string, unknown>; }

export interface ContinuousAssurancePreview {
  policyDigest: string;
  target: { id: string; origin: string; rowVersion: number };
  adapterBindings: Array<{ profileId: string; versionId: string; adapterDigest: string; maximumDurationMs: number; maxRequests: number; cleanupReservedRequests: number }>;
  authorization: { validNow: boolean; validThroughEstimatedCompletion: boolean; expiresAt: string };
  estimate: { maximumDurationMs: number; maxRequests: number; cleanupReservedRequests: number };
  blockers: string[];
  warnings: string[];
}

export class ContinuousAssuranceService {
  private readonly installationId: string;
  private readonly timer?: ReturnType<typeof setInterval>;
  private reconciling = false;

  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly execution: ExecutionPort | ScanExecutionService,
    private readonly adapters: AdapterPort | ProviderAdapterService,
    private readonly comparisons: ComparisonPort | ScanComparisonService,
    private readonly evidence: EvidencePort | EvidenceGovernanceService,
    options: { startTimers?: boolean; intervalMs?: number } = {}
  ) {
    this.installationId = (database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as { value: string }).value;
    if (options.startTimers !== false) {
      this.timer = setInterval(() => void this.tick(), options.intervalMs ?? 15_000);
      this.timer.unref();
      void this.tick();
    }
  }

  public shutdown(): void { if (this.timer) clearInterval(this.timer); }

  public async preview(value: unknown): Promise<ContinuousAssurancePreview> {
    const input = continuousAssurancePolicyInputSchema.parse(value);
    const target = this.database.db.prepare("SELECT id,base_origin,row_version FROM targets WHERE id=? AND archived_at IS NULL").get(input.targetId) as { id: string; base_origin: string; row_version: number } | undefined;
    if (!target) throw new Error("CONTINUOUS_ASSURANCE_TARGET_NOT_FOUND");
    const blockers: string[] = [], warnings: string[] = [];
    const bindings: ContinuousAssurancePreview["adapterBindings"] = [];
    for (const profileId of input.adapterProfileIds) {
      try {
        const materialized = this.adapters.materialize(profileId);
        if (materialized.target.id !== target.id || materialized.input.targetId !== target.id) blockers.push(`Adapter ${profileId} belongs to another target.`);
        const request = this.adapters.materializeScanRequest(profileId);
        await this.adapters.assertExecutionBinding(request);
        const plan = await this.execution.preview(request);
        const readiness = plan.credentialReadiness;
        blockers.push(...readiness.blockers.map((item) => `${profileId}: ${item.code}: ${item.message}`));
        warnings.push(...readiness.warnings.map((item) => `${profileId}: ${item.code}: ${item.message}`));
        const maximumDurationMs = numberField(plan.limits, "maxScanDurationMs");
        const requiredValidThrough = Date.now() + bindings.reduce((sum,item)=>sum+item.maximumDurationMs,0) + maximumDurationMs;
        for (const profile of readiness.profiles) if (profile.expiresAt && Date.parse(profile.expiresAt) <= requiredValidThrough) blockers.push(`${profileId}: credential ${profile.role} expires before its queued adapter can finish.`);
        bindings.push({ ...materialized.binding, maximumDurationMs, maxRequests: numberField(plan.limits, "maxRequests"), cleanupReservedRequests: numberField(plan.limits, "cleanupReservedRequests") });
      } catch (error) { blockers.push(`${profileId}: ${safeError(error)}`); }
    }
    for (const baseline of input.baselines) {
      const scan = this.database.db.prepare("SELECT id,target_id,status FROM scans WHERE id=? AND deleted_at IS NULL").get(baseline.scanId) as { id: string; target_id: string | null; status: string } | undefined;
      if (!scan || scan.target_id !== target.id || !["COMPLETED", "IMPORTED"].includes(scan.status)) blockers.push(`Baseline ${baseline.scanId} is unavailable, incomplete, or belongs to another target.`);
      const bound = this.database.db.prepare("SELECT profile_id FROM scan_provider_adapter_bindings WHERE scan_id=?").get(baseline.scanId) as { profile_id: string } | undefined;
      if (!bound || bound.profile_id !== baseline.adapterProfileId) blockers.push(`Baseline ${baseline.scanId} is not bound to adapter ${baseline.adapterProfileId}.`);
    }
    if (input.baselines.length !== input.adapterProfileIds.length) blockers.push("Every adapter requires one explicit completed baseline bound to that adapter.");
    for (const required of input.requiredCases) {
      const baseline=input.baselines.find(item=>item.adapterProfileId===required.adapterProfileId);
      const exists=baseline&&this.database.db.prepare("SELECT 1 FROM scan_workflow_case_executions WHERE scan_id=? AND workflow_id=? AND safe_case_fingerprint=? AND execution_state='COMPLETED' AND request_transmitted=1 AND matched_expectation=1").get(baseline.scanId,required.workflowId,required.caseFingerprint);
      if(!exists)blockers.push(`Required case ${required.workflowId}/${required.caseFingerprint.slice(0,12)} is not proven in adapter ${required.adapterProfileId}'s baseline.`);
    }
    const maximumDurationMs = bindings.reduce((sum, item) => sum + item.maximumDurationMs, 0);
    const now = Date.now(), starts = Date.parse(input.authorization.validFrom), expires = Date.parse(input.authorization.expiresAt);
    const authorization = { validNow: starts <= now && expires > now, validThroughEstimatedCompletion: starts <= now && expires > now + maximumDurationMs, expiresAt: input.authorization.expiresAt };
    if (!authorization.validNow) blockers.push("Authorization is not currently valid.");
    else if (!authorization.validThroughEstimatedCompletion) blockers.push("Authorization expires before the worst-case run duration completes.");
    else if (input.triggers.scheduleEnabled && expires <= now + input.triggers.intervalMinutes * 60_000 + maximumDurationMs) blockers.push("Authorization expires before the next scheduled run could finish; renew authorization or disable scheduling.");
    const cleanup = await readMutationCleanupStatus(this.paths.mutationJournalDir, this.paths.mutationJournalRegistryPath);
    if (cleanup.cleanupRequired > 0) blockers.push(`${cleanup.cleanupRequired} unresolved mutation cleanup obligation(s) block continuous execution.`);
    if (input.evidence.autoExportOn.length && !this.evidence.available()) blockers.push("Encrypted evidence export requires the dashboard vault key.");
    const canonical = { input, target: { id: target.id, origin: target.base_origin, rowVersion: target.row_version }, adapterBindings: bindings.map(({ profileId, versionId, adapterDigest }) => ({ profileId, versionId, adapterDigest })) };
    return { policyDigest: digest(canonical), target: { id: target.id, origin: target.base_origin, rowVersion: target.row_version }, adapterBindings: bindings, authorization, estimate: { maximumDurationMs, maxRequests: bindings.reduce((sum,item)=>sum+item.maxRequests,0), cleanupReservedRequests: bindings.reduce((sum,item)=>sum+item.cleanupReservedRequests,0) }, blockers, warnings };
  }

  public async create(value: unknown, actor: string): Promise<Record<string, unknown>> {
    const input = continuousAssurancePolicyInputSchema.parse(value), preview = await this.preview(input);
    if (preview.blockers.length) throw new Error(`CONTINUOUS_ASSURANCE_INVALID: ${preview.blockers.join(" ")}`);
    const id = randomUUID(), versionId = randomUUID(), token = randomBytes(32).toString("base64url"), now = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO continuous_assurance_policies (id,name,description,target_id,status,pending_version_id,trigger_token_hash,trigger_token_rotated_at,created_by,created_at,updated_at) VALUES (?,?,?,?,'DRAFT',?,?,?,?,?,?)").run(id,input.name,input.description||null,input.targetId,versionId,sha256(token),now,actor,now,now);
      this.insertVersion(id,versionId,1,input,preview,actor,now);
    });
    return { policy: this.get(id), deploymentTriggerToken: token, warning: "This deployment trigger token is shown once. Store it in the deployment system's secret vault." };
  }

  public async update(id: string, value: unknown, actor: string): Promise<Record<string, unknown>> {
    const policy = this.policyRow(id), input = continuousAssurancePolicyInputSchema.parse(value);
    if (input.targetId !== policy.target_id) throw new Error("CONTINUOUS_ASSURANCE_TARGET_IMMUTABLE");
    const preview = await this.preview(input); if (preview.blockers.length) throw new Error(`CONTINUOUS_ASSURANCE_INVALID: ${preview.blockers.join(" ")}`);
    const revision = (this.database.db.prepare("SELECT COALESCE(MAX(revision),0) revision FROM continuous_assurance_policy_versions WHERE policy_id=?").get(id) as { revision: number }).revision + 1;
    const versionId=randomUUID(), now=nowIso();
    this.database.transaction(()=>{ this.database.db.prepare("UPDATE continuous_assurance_policy_versions SET status='SUPERSEDED' WHERE policy_id=? AND status='DRAFT'").run(id); this.insertVersion(id,versionId,revision,input,preview,actor,now); this.database.db.prepare("UPDATE continuous_assurance_policies SET name=?,description=?,status='DRAFT',pending_version_id=?,next_due_at=NULL,updated_at=?,row_version=row_version+1 WHERE id=?").run(input.name,input.description||null,versionId,now,id); });
    return this.get(id);
  }

  public async review(id: string, versionId: string, policyDigest: string, actor: string): Promise<Record<string, unknown>> {
    const row=this.versionRow(id,versionId); if(row.status!=="DRAFT") throw new Error("CONTINUOUS_ASSURANCE_DRAFT_REQUIRED");
    const input=continuousAssurancePolicyInputSchema.parse(JSON.parse(row.policy_json)), preview=await this.preview(input);
    if(preview.blockers.length) throw new Error(`CONTINUOUS_ASSURANCE_REVIEW_BLOCKED: ${preview.blockers.join(" ")}`);
    if(policyDigest!==row.policy_digest||policyDigest!==preview.policyDigest||row.target_row_version!==preview.target.rowVersion||row.adapter_bindings_json!==JSON.stringify(bindingIdentity(preview))) throw new Error("CONTINUOUS_ASSURANCE_REVIEW_BINDING_CHANGED");
    const now=nowIso(), next=input.triggers.scheduleEnabled?new Date(Date.now()+input.triggers.intervalMinutes*60_000).toISOString():null;
    this.database.transaction(()=>{ this.database.db.prepare("UPDATE continuous_assurance_policy_versions SET status='SUPERSEDED' WHERE policy_id=? AND status='REVIEWED'").run(id); const changed=this.database.db.prepare("UPDATE continuous_assurance_policy_versions SET status='REVIEWED',reviewed_by=?,reviewed_at=? WHERE id=? AND policy_id=? AND status='DRAFT'").run(actor,now,versionId,id); if(changed.changes!==1) throw new Error("CONTINUOUS_ASSURANCE_REVIEW_CONFLICT"); this.database.db.prepare("UPDATE continuous_assurance_policies SET status='ACTIVE',active_version_id=?,pending_version_id=NULL,next_due_at=?,updated_at=?,row_version=row_version+1 WHERE id=?").run(versionId,next,now,id); });
    return this.get(id);
  }

  public list(): Record<string, unknown>[] { return (this.database.db.prepare("SELECT id FROM continuous_assurance_policies WHERE deleted_at IS NULL ORDER BY updated_at DESC LIMIT 200").all() as Array<{id:string}>).map(({id})=>this.get(id)); }
  public get(id:string):Record<string,unknown>{ const row=this.policyRow(id), versionRows=this.database.db.prepare("SELECT * FROM continuous_assurance_policy_versions WHERE policy_id=? ORDER BY revision DESC").all(id) as VersionRowWithRevision[], versions=versionRows.map(v=>({id:v.id,revision:v.revision,status:v.status,policyDigest:v.policy_digest,targetRowVersion:v.target_row_version,createdAt:v.created_at,reviewedAt:v.reviewed_at})); const runs=this.database.db.prepare("SELECT id,trigger_type triggerType,trigger_reference triggerReference,build_fingerprint buildFingerprint,status,gate_status gateStatus,safe_summary_json safeSummaryJson,notification_required notificationRequired,created_at createdAt,started_at startedAt,completed_at completedAt FROM continuous_assurance_runs WHERE policy_id=? ORDER BY created_at DESC LIMIT 25").all(id) as Array<Record<string,unknown>&{safeSummaryJson:string;notificationRequired:number}>; const pending=versionRows.find(v=>v.id===row.pending_version_id),active=versionRows.find(v=>v.id===row.active_version_id); return { id:row.id,name:row.name,description:row.description,targetId:row.target_id,status:row.status,activeVersionId:row.active_version_id,pendingVersionId:row.pending_version_id,nextDueAt:row.next_due_at,lastRunAt:row.last_run_at,rowVersion:row.row_version,versions,...(pending?{pendingInput:continuousAssurancePolicyInputSchema.parse(JSON.parse(pending.policy_json))}:{}),...(active?{activeInput:continuousAssurancePolicyInputSchema.parse(JSON.parse(active.policy_json))}:{}),runs:runs.map(v=>({...v,safeSummary:parse(String(v.safeSummaryJson),{}),notificationRequired:Boolean(v.notificationRequired),safeSummaryJson:undefined})),impact:this.impact(id) }; }
  public activeInput(id:string):ContinuousAssurancePolicyInput { const p=this.policyRow(id); if(!p.active_version_id) throw new Error("CONTINUOUS_ASSURANCE_REVIEWED_VERSION_REQUIRED"); return continuousAssurancePolicyInputSchema.parse(JSON.parse(this.versionRow(id,p.active_version_id).policy_json)); }

  public impact(id:string):Record<string,unknown>{ const activeRuns=(this.database.db.prepare("SELECT COUNT(*) count FROM continuous_assurance_runs WHERE policy_id=? AND status IN ('LAUNCHING','RUNNING')").get(id) as {count:number}).count; const value={activeRuns}; return {...value,canDisable:activeRuns===0,impactDigest:digest({id,...value})}; }
  public setEnabled(id:string,enabled:boolean,impactDigest:string):Record<string,unknown>{ const impact=this.impact(id); if(impact.impactDigest!==impactDigest) throw new Error("CONTINUOUS_ASSURANCE_IMPACT_CHANGED"); const p=this.policyRow(id); if(enabled&&p.status!=="DISABLED") throw new Error("CONTINUOUS_ASSURANCE_DISABLED_POLICY_REQUIRED"); if(!enabled&&p.status!=="ACTIVE") throw new Error("CONTINUOUS_ASSURANCE_ACTIVE_POLICY_REQUIRED"); if(enabled&&!p.active_version_id) throw new Error("CONTINUOUS_ASSURANCE_REVIEWED_VERSION_REQUIRED"); if(!enabled&&!impact.canDisable) throw new Error("CONTINUOUS_ASSURANCE_ACTIVE_RUN"); const input=enabled?this.activeInput(id):undefined; this.database.db.prepare("UPDATE continuous_assurance_policies SET status=?,next_due_at=?,updated_at=?,row_version=row_version+1 WHERE id=?").run(enabled?"ACTIVE":"DISABLED",enabled&&input?.triggers.scheduleEnabled?new Date(Date.now()+input.triggers.intervalMinutes*60_000).toISOString():null,nowIso(),id); return this.get(id); }
  public rotateTriggerToken(id:string,actor:string):Record<string,unknown>{ this.policyRow(id); const token=randomBytes(32).toString("base64url"), now=nowIso(); this.database.db.prepare("UPDATE continuous_assurance_policies SET trigger_token_hash=?,trigger_token_rotated_at=?,updated_at=?,row_version=row_version+1 WHERE id=?").run(sha256(token),now,now,id); return { policyId:id,deploymentTriggerToken:token,rotatedBy:actor,rotatedAt:now,warning:"The prior token is invalid. This replacement is shown once." }; }

  public async runNow(id:string,actor:string):Promise<Record<string,unknown>>{ return this.startRun(id,"MANUAL",actor); }
  public async deployment(id:string, token:string, deploymentId:string, buildFingerprint:string):Promise<Record<string,unknown>> {
    const policy=this.policyRow(id); if(policy.status!=="ACTIVE") throw new Error("CONTINUOUS_ASSURANCE_TRIGGER_REJECTED");
    const input=this.activeInput(id); if(!input.triggers.deploymentEnabled||!constantEqual(sha256(token),policy.trigger_token_hash)) throw new Error("CONTINUOUS_ASSURANCE_TRIGGER_REJECTED");
    const existing=this.database.db.prepare("SELECT run_id,build_fingerprint FROM continuous_assurance_deployments WHERE policy_id=? AND deployment_id=?").get(id,deploymentId) as {run_id:string|null;build_fingerprint:string}|undefined;
    if(existing){ if(existing.build_fingerprint!==buildFingerprint) throw new Error("CONTINUOUS_ASSURANCE_DEPLOYMENT_REPLAY_MISMATCH"); return {accepted:true,idempotentReplay:true,runId:existing.run_id}; }
    this.database.db.prepare("INSERT INTO continuous_assurance_deployments (policy_id,deployment_id,build_fingerprint,received_at) VALUES (?,?,?,?)").run(id,deploymentId,buildFingerprint,nowIso());
    try { const run=await this.startRun(id,"DEPLOYMENT","deployment-hook",deploymentId,buildFingerprint) as {id:string}; this.database.db.prepare("UPDATE continuous_assurance_deployments SET run_id=? WHERE policy_id=? AND deployment_id=?").run(run.id,id,deploymentId); return {accepted:true,idempotentReplay:false,runId:run.id}; }
    catch(error){ this.database.db.prepare("DELETE FROM continuous_assurance_deployments WHERE policy_id=? AND deployment_id=? AND run_id IS NULL").run(id,deploymentId); throw error; }
  }

  public notifications():Record<string,unknown>[] { return this.database.db.prepare("SELECT id,run_id runId,category,severity,safe_summary safeSummary,created_at createdAt,acknowledged_by acknowledgedBy,acknowledged_at acknowledgedAt FROM continuous_assurance_notifications ORDER BY created_at DESC LIMIT 200").all() as Record<string,unknown>[]; }
  public acknowledge(notificationId:string,actor:string):void { const changed=this.database.db.prepare("UPDATE continuous_assurance_notifications SET acknowledged_by=?,acknowledged_at=? WHERE id=? AND acknowledged_at IS NULL").run(actor,nowIso(),notificationId); if(changed.changes!==1) throw new Error("CONTINUOUS_ASSURANCE_NOTIFICATION_UNAVAILABLE"); }

  public async processDueNow():Promise<void>{ await this.processDue(); }
  public async reconcileNow():Promise<void>{ await this.reconcile(); }
  private async tick():Promise<void>{ if(this.reconciling||!this.database.db.open)return; this.reconciling=true; try{await this.reconcile();await this.processDue();}finally{this.reconciling=false;} }
  private async processDue():Promise<void>{ const due=this.database.db.prepare("SELECT id FROM continuous_assurance_policies WHERE status='ACTIVE' AND next_due_at IS NOT NULL AND next_due_at<=? ORDER BY next_due_at LIMIT 5").all(nowIso()) as Array<{id:string}>; for(const {id} of due){ try{await this.startRun(id,"SCHEDULE","scheduler");}catch(error){this.recordBlockedSchedule(id,safeError(error));} } }

  private async startRun(policyId:string,trigger:TriggerType,actor:string,reference?:string,buildFingerprint?:string):Promise<Record<string,unknown>>{
    const policy=this.policyRow(policyId); if(policy.status!=="ACTIVE"||!policy.active_version_id) throw new Error("CONTINUOUS_ASSURANCE_ACTIVE_REVIEWED_POLICY_REQUIRED");
    const existing=this.database.db.prepare("SELECT id FROM continuous_assurance_runs WHERE policy_id=? AND status IN ('LAUNCHING','RUNNING')").get(policyId) as {id:string}|undefined;
    if(existing){if(trigger==="SCHEDULE"){const scheduled=this.activeInput(policyId);this.database.db.prepare("UPDATE continuous_assurance_policies SET next_due_at=?,updated_at=? WHERE id=?").run(new Date(Date.now()+scheduled.triggers.intervalMinutes*60_000).toISOString(),nowIso(),policyId);return this.run(existing.id);}throw new Error("CONTINUOUS_ASSURANCE_RUN_ALREADY_ACTIVE");}
    const input=this.activeInput(policyId), preview=await this.preview(input); if(preview.blockers.length) throw new Error(`CONTINUOUS_ASSURANCE_RUN_BLOCKED: ${preview.blockers.join(" ")}`);
    const version=this.versionRow(policyId,policy.active_version_id); if(version.policy_digest!==preview.policyDigest||version.adapter_bindings_json!==JSON.stringify(bindingIdentity(preview))) throw new Error("CONTINUOUS_ASSURANCE_POLICY_DRIFT");
    const leaseToken=this.acquireLease(policyId), runId=randomUUID(), now=nowIso();
    try{
      this.database.transaction(()=>{ this.database.db.prepare("INSERT INTO continuous_assurance_runs (id,policy_id,version_id,policy_digest,trigger_type,trigger_reference,build_fingerprint,status,gate_status,requested_by,installation_id,created_at,started_at) VALUES (?,?,?,?,?,?,?,'LAUNCHING','PENDING',?,?,?,?)").run(runId,policyId,version.id,version.policy_digest,trigger,reference??null,buildFingerprint??null,actor,this.installationId,now,now); const insert=this.database.db.prepare("INSERT INTO continuous_assurance_run_scans (id,run_id,adapter_profile_id,adapter_version_id,adapter_digest,status,ordinal) VALUES (?,?,?,?,?,'PENDING',?)"); preview.adapterBindings.forEach((binding,index)=>insert.run(randomUUID(),runId,binding.profileId,binding.versionId,binding.adapterDigest,index)); this.database.db.prepare("UPDATE continuous_assurance_policies SET last_run_at=?,next_due_at=?,updated_at=? WHERE id=?").run(now,input.triggers.scheduleEnabled?new Date(Date.now()+input.triggers.intervalMinutes*60_000).toISOString():null,now,policyId); });
      let queued=0;
      for(const binding of preview.adapterBindings){ try{ const request=this.adapters.materializeScanRequest(binding.profileId); await this.adapters.assertExecutionBinding(request); const scanId=await this.execution.enqueue(request); this.adapters.bindScan(scanId,binding); this.database.db.prepare("UPDATE continuous_assurance_run_scans SET scan_id=?,status='QUEUED' WHERE run_id=? AND adapter_profile_id=?").run(scanId,runId,binding.profileId); queued++; } catch(error){ this.database.db.prepare("UPDATE continuous_assurance_run_scans SET status='BLOCKED',safe_error_summary=? WHERE run_id=? AND adapter_profile_id=?").run(safeError(error),runId,binding.profileId); } }
      this.database.db.prepare("UPDATE continuous_assurance_runs SET status='RUNNING' WHERE id=?").run(runId);
      if(!queued) await this.finalize(runId);
      return this.run(runId);
    } finally { this.releaseLease(policyId,leaseToken); }
  }

  private async reconcile():Promise<void>{ const runs=this.database.db.prepare("SELECT id FROM continuous_assurance_runs WHERE status IN ('LAUNCHING','RUNNING') ORDER BY created_at").all() as Array<{id:string}>; for(const {id} of runs){ const lanes=this.database.db.prepare("SELECT id,scan_id,status FROM continuous_assurance_run_scans WHERE run_id=?").all(id) as Array<{id:string;scan_id:string|null;status:string}>; let active=false; for(const lane of lanes){ if(!lane.scan_id)continue; const scan=this.database.db.prepare("SELECT status FROM scans WHERE id=?").get(lane.scan_id) as {status:string}|undefined; if(!scan){this.database.db.prepare("UPDATE continuous_assurance_run_scans SET status='FAILED',safe_error_summary='Bound scan is unavailable.' WHERE id=?").run(lane.id);continue;} if(["QUEUED","PLANNING","RUNNING","CANCEL_REQUESTED"].includes(scan.status)){active=true;continue;} const state=scan.status==="COMPLETED"||scan.status==="IMPORTED"?"COMPLETED":scan.status==="CANCELLED"?"CANCELLED":"FAILED"; this.database.db.prepare("UPDATE continuous_assurance_run_scans SET status=? WHERE id=?").run(state,lane.id); } if(!active)await this.finalize(id); } }

  private async finalize(runId:string):Promise<void>{ const run=this.runRow(runId); if(["COMPLETED","FAILED","BLOCKED","CANCELLED"].includes(run.status))return; const input=continuousAssurancePolicyInputSchema.parse(JSON.parse(this.versionRow(run.policy_id,run.version_id).policy_json)); const lanes=this.database.db.prepare("SELECT adapter_profile_id,scan_id,status FROM continuous_assurance_run_scans WHERE run_id=? ORDER BY ordinal").all(runId) as Array<{adapter_profile_id:string;scan_id:string|null;status:string}>; const failures=lanes.filter(v=>v.status!=="COMPLETED"), scanIds=lanes.flatMap(v=>v.scan_id?[v.scan_id]:[]), comparisonIds:string[]=[]; let regressions=0,newFindings=0,incomparable=0,notRetested=0;
    for(const lane of lanes){ const baseline=input.baselines.find(v=>v.adapterProfileId===lane.adapter_profile_id); if(!baseline||!lane.scan_id){incomparable++;continue;} try{const c=this.comparisons.compare(baseline.scanId,lane.scan_id);comparisonIds.push(c.comparisonId);regressions+=c.summary.regressions+c.summary.severityIncreases;newFindings+=c.summary.new;incomparable+=c.summary.incomparable;notRetested+=c.summary.notRetested;}catch{incomparable++;} }
    let missingCases=0; for(const required of input.requiredCases){ const scanId=lanes.find(lane=>lane.adapter_profile_id===required.adapterProfileId)?.scan_id; const found=scanId&&this.database.db.prepare("SELECT 1 FROM scan_workflow_case_executions WHERE scan_id=? AND workflow_id=? AND safe_case_fingerprint=? AND execution_state='COMPLETED' AND request_transmitted=1 AND matched_expectation=1").get(scanId,required.workflowId,required.caseFingerprint); if(!found)missingCases++; }
    const cleanup=await readMutationCleanupStatus(this.paths.mutationJournalDir,this.paths.mutationJournalRegistryPath); const cleanupRows=scanIds.reduce((sum,id)=>sum+(this.database.db.prepare("SELECT COUNT(*) count FROM assisted_case_results WHERE scan_id=? AND cleanup_unresolved=1").get(id) as {count:number}).count,0); const approvals=scanIds.reduce((sum,id)=>sum+(this.database.db.prepare("SELECT COUNT(*) count FROM controlled_mutation_approvals WHERE execution_scan_id=? AND status IN ('EXECUTING','CLEANUP_REQUIRED','CLEANUP_FAILED')").get(id) as {count:number}).count,0); const unresolvedCleanup=cleanup.cleanupRequired+cleanupRows+approvals;
    const openDrift=scanIds.reduce((sum,id)=>sum+(this.database.db.prepare("SELECT COUNT(*) count FROM adaptive_security_drifts d JOIN adaptive_security_snapshots s ON s.id=d.snapshot_id WHERE s.source_scan_id=? AND d.status='OPEN'").get(id) as {count:number}).count,0);
    const regressionGate=regressions>0||(input.gates.failOnNewFinding&&newFindings>0); const inconclusive=incomparable>0||notRetested>0||missingCases>0; const blocked=failures.length>0||unresolvedCleanup>0||(input.gates.failOnOpenDrift&&openDrift>0); const gate=blocked?"BLOCKED":regressionGate?"REGRESSION":inconclusive?"INCONCLUSIVE":"PASSED"; const status:RunState=failures.length?"FAILED":"COMPLETED"; const summary={scanCount:scanIds.length,failedLanes:failures.length,regressions,newFindings,incomparable,notRetested,missingExactCases:missingCases,unresolvedCleanup,openDrift,quiet:gate==="PASSED"};
    const categories:Array<"REGRESSION"|"FAILED"|"CLEANUP_REQUIRED"|"APPROVAL_REQUIRED">=[]; if(regressionGate)categories.push("REGRESSION"); if(failures.length)categories.push("FAILED"); if(unresolvedCleanup)categories.push("CLEANUP_REQUIRED"); if(inconclusive||(input.gates.failOnOpenDrift&&openDrift>0))categories.push("APPROVAL_REQUIRED");
    this.database.transaction(()=>{this.database.db.prepare("UPDATE continuous_assurance_runs SET status=?,gate_status=?,safe_summary_json=?,comparison_ids_json=?,notification_required=?,completed_at=? WHERE id=?").run(status,gate,JSON.stringify(summary),JSON.stringify(comparisonIds),categories.length?1:0,nowIso(),runId); for(const category of categories)this.database.db.prepare("INSERT INTO continuous_assurance_notifications (id,run_id,category,severity,safe_summary,created_at) VALUES (?,?,?,?,?,?)").run(randomUUID(),runId,category,category==="REGRESSION"||category==="CLEANUP_REQUIRED"?"CRITICAL":"WARNING",notificationSummary(category,summary),nowIso());});
    const exportEvent=categories.find(v=>input.evidence.autoExportOn.includes(v)); if(exportEvent&&scanIds.length){try{const exported=this.evidence.createExport(scanIds,`continuous-assurance:${runId}`);this.mergeRunSummary(runId,{evidenceExport:exported});}catch(error){this.notify(runId,"APPROVAL_REQUIRED",`Automatic encrypted evidence export failed: ${safeError(error)}`);}}
  }

  private run(id:string):Record<string,unknown>{const r=this.runRow(id),lanes=this.database.db.prepare("SELECT adapter_profile_id adapterProfileId,adapter_version_id adapterVersionId,adapter_digest adapterDigest,scan_id scanId,status,safe_error_summary safeErrorSummary,ordinal FROM continuous_assurance_run_scans WHERE run_id=? ORDER BY ordinal").all(id);return{id:r.id,policyId:r.policy_id,versionId:r.version_id,policyDigest:r.policy_digest,triggerType:r.trigger_type,triggerReference:r.trigger_reference,buildFingerprint:r.build_fingerprint,status:r.status,gateStatus:r.gate_status,safeSummary:parse(r.safe_summary_json,{}),comparisonIds:parse(r.comparison_ids_json,[]),notificationRequired:Boolean(r.notification_required),createdAt:r.created_at,startedAt:r.started_at,completedAt:r.completed_at,lanes};}
  private insertVersion(policyId:string,id:string,revision:number,input:ContinuousAssurancePolicyInput,preview:ContinuousAssurancePreview,actor:string,created:string):void{this.database.db.prepare("INSERT INTO continuous_assurance_policy_versions (id,policy_id,revision,status,policy_digest,target_row_version,policy_json,adapter_bindings_json,created_by,created_at) VALUES (?,?,?,'DRAFT',?,?,?,?,?,?)").run(id,policyId,revision,preview.policyDigest,preview.target.rowVersion,JSON.stringify(input),JSON.stringify(bindingIdentity(preview)),actor,created);}
  private acquireLease(policyId:string):string{const token=randomUUID(),now=nowIso(),expires=new Date(Date.now()+120_000).toISOString(); this.database.transaction(()=>{const row=this.database.db.prepare("SELECT owner_installation_id,lease_expires_at FROM continuous_assurance_leases WHERE policy_id=?").get(policyId) as {owner_installation_id:string;lease_expires_at:string}|undefined;if(row&&row.lease_expires_at>now)throw new Error("CONTINUOUS_ASSURANCE_POLICY_LEASED");this.database.db.prepare("INSERT INTO continuous_assurance_leases (policy_id,owner_installation_id,lease_token,lease_expires_at,heartbeat_at) VALUES (?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET owner_installation_id=excluded.owner_installation_id,lease_token=excluded.lease_token,lease_expires_at=excluded.lease_expires_at,heartbeat_at=excluded.heartbeat_at").run(policyId,this.installationId,token,expires,now);});return token;}
  private releaseLease(policyId:string,token:string):void{this.database.db.prepare("DELETE FROM continuous_assurance_leases WHERE policy_id=? AND owner_installation_id=? AND lease_token=?").run(policyId,this.installationId,token);}
  private policyRow(id:string):PolicyRow{const row=this.database.db.prepare("SELECT * FROM continuous_assurance_policies WHERE id=? AND deleted_at IS NULL").get(id) as PolicyRow|undefined;if(!row)throw new Error("CONTINUOUS_ASSURANCE_POLICY_NOT_FOUND");return row;}
  private versionRow(policyId:string,id:string):VersionRow{const row=this.database.db.prepare("SELECT * FROM continuous_assurance_policy_versions WHERE id=? AND policy_id=?").get(id,policyId) as VersionRow|undefined;if(!row)throw new Error("CONTINUOUS_ASSURANCE_VERSION_NOT_FOUND");return row;}
  private runRow(id:string):RunRow{const row=this.database.db.prepare("SELECT * FROM continuous_assurance_runs WHERE id=?").get(id) as RunRow|undefined;if(!row)throw new Error("CONTINUOUS_ASSURANCE_RUN_NOT_FOUND");return row;}
  private mergeRunSummary(id:string,patch:Record<string,unknown>):void{const row=this.runRow(id);this.database.db.prepare("UPDATE continuous_assurance_runs SET safe_summary_json=? WHERE id=?").run(JSON.stringify({...parse(row.safe_summary_json,{}),...patch}),id);}
  private notify(runId:string,category:"REGRESSION"|"FAILED"|"CLEANUP_REQUIRED"|"APPROVAL_REQUIRED",summary:string):void{this.database.db.prepare("INSERT INTO continuous_assurance_notifications (id,run_id,category,severity,safe_summary,created_at) VALUES (?,?,?,?,?,?)").run(randomUUID(),runId,category,category==="REGRESSION"||category==="CLEANUP_REQUIRED"?"CRITICAL":"WARNING",summary,nowIso());this.database.db.prepare("UPDATE continuous_assurance_runs SET notification_required=1 WHERE id=?").run(runId);}
  private recordBlockedSchedule(policyId:string,reason:string):void{const policy=this.policyRow(policyId);if(!policy.active_version_id)return;const input=this.activeInput(policyId),id=randomUUID(),now=nowIso(),authorizationExpired=Date.parse(input.authorization.expiresAt)<=Date.now();this.database.transaction(()=>{this.database.db.prepare("INSERT INTO continuous_assurance_runs (id,policy_id,version_id,policy_digest,trigger_type,status,gate_status,requested_by,installation_id,safe_summary_json,notification_required,created_at,started_at,completed_at) SELECT ?,p.id,v.id,v.policy_digest,'SCHEDULE','BLOCKED','BLOCKED','scheduler',?, ?,1,?,?,? FROM continuous_assurance_policies p JOIN continuous_assurance_policy_versions v ON v.id=p.active_version_id WHERE p.id=?").run(id,this.installationId,JSON.stringify({blockedBeforeExecution:true,reason,authorizationExpired}),now,now,now,policyId);this.database.db.prepare("INSERT INTO continuous_assurance_notifications (id,run_id,category,severity,safe_summary,created_at) VALUES (?,?,'FAILED','WARNING',?,?)").run(randomUUID(),id,`Scheduled assurance was blocked before target traffic: ${reason}`,now);this.database.db.prepare("UPDATE continuous_assurance_policies SET status=?,next_due_at=?,last_run_at=?,updated_at=? WHERE id=?").run(authorizationExpired?"DISABLED":"ACTIVE",authorizationExpired?null:new Date(Date.now()+input.triggers.intervalMinutes*60_000).toISOString(),now,now,policyId);});}
}

function bindingIdentity(preview:ContinuousAssurancePreview){return preview.adapterBindings.map(({profileId,versionId,adapterDigest})=>({profileId,versionId,adapterDigest}));}
function numberField(value:Record<string,unknown>,key:string):number{const n=value[key];return typeof n==="number"&&Number.isFinite(n)?n:0;}
function safeError(error:unknown):string{return error instanceof Error?clamp(error.message,800):"Continuous assurance operation failed.";}
function sha256(value:string|Buffer):string{return createHash("sha256").update(value).digest("hex");}
function digest(value:unknown):string{return sha256(JSON.stringify(sort(value)));}
function sort(value:unknown):unknown{if(Array.isArray(value))return value.map(sort);if(!value||typeof value!=="object")return value;return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sort(v)]));}
function parse<T>(value:string,fallback:T):T{try{return JSON.parse(value) as T;}catch{return fallback;}}
function constantEqual(a:string,b:string):boolean{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
function notificationSummary(category:string,summary:Record<string,unknown>):string{return `${category.replaceAll("_"," ")}: ${Object.entries(summary).filter(([,v])=>typeof v==="number"&&v>0).map(([k,v])=>`${k}=${v}`).join(", ")||"operator attention required"}.`;}
interface PolicyRow{id:string;name:string;description:string|null;target_id:string;status:string;active_version_id:string|null;pending_version_id:string|null;trigger_token_hash:string;next_due_at:string|null;last_run_at:string|null;row_version:number;}
interface VersionRow{id:string;policy_id:string;status:string;policy_digest:string;target_row_version:number;policy_json:string;adapter_bindings_json:string;}
interface VersionRowWithRevision extends VersionRow { revision:number;created_at:string;reviewed_at:string|null; }
interface RunRow{id:string;policy_id:string;version_id:string;policy_digest:string;trigger_type:string;trigger_reference:string|null;build_fingerprint:string|null;status:string;gate_status:string;safe_summary_json:string;comparison_ids_json:string;notification_required:number;created_at:string;started_at:string|null;completed_at:string|null;}
