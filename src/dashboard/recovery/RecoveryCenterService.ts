import {CleanupAttemptLedger} from "./CleanupAttemptLedger.js";
import { createHash, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { AuditRepository } from "../db/DashboardRepositories.js";
import type { WorkflowRecoveryService } from "../execution/WorkflowRecoveryService.js";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { assertComparisonSummary, assertAssuranceComparison } from "../comparisons/ComparisonIntegrity.js";
import {
  recoveryReviewSchema,
  recoveryRecomputeSchema,
  type RecoveryScope,
  type RecoveryIssue,
  type RecoveryCenterSnapshot
} from "../contracts/RecoveryCenterContracts.js";

type Row = Record<string, any>;
const sha = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const parse = (text: string): Row => {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Row) : {};
  } catch {
    return {};
  }
};
export class RecoveryOperationError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
  }
}

/** A projection of uncertainty, not a new source of execution or clearance authority. */
export class RecoveryCenterService {
  private readonly snapshots = new Map<string, () => string>();
  constructor(
    private readonly db: DashboardDatabase,
    private readonly workflow: Pick<WorkflowRecoveryService, "inventory">
  ) {}

  private boundRow(kind: string, row: Row): Row {
    if (kind !== "COMPARISON") return row;
    return {
      ...row,
      coverageEvidence: [
        "scan_comparison_module_coverage",
        "scan_comparison_workflow_coverage",
        "scan_comparison_case_coverage"
      ].map((table) =>
        this.db.db.prepare("SELECT * FROM " + table + " WHERE comparison_id=? ORDER BY rowid").all(row.id)
      )
    };
  }

  public async workflowInventory(organizationId: string) {
    const inventory = await this.workflow.inventory();
    const targets = this.db.db
      .prepare("SELECT id,base_origin FROM targets WHERE organization_id=? AND archived_at IS NULL")
      .all(organizationId) as { id: string; base_origin: string }[];
    const ownedOrigins = new Set(
      targets.filter((t) => this.originOwned(t.base_origin, organizationId)).map((t) => t.base_origin)
    );
    const cases = inventory.cases
      .filter((item) => item.targetOrigin && ownedOrigins.has(item.targetOrigin))
      .map((item) => ({
        caseId: item.caseId,
        journalId: item.journalId,
        stage: item.stage,
        targetOrigin: item.targetOrigin,
        recoveryKind: item.recoveryKind,
        ...("checkpointDigest" in item
          ? {
              checkpointDigest: item.checkpointDigest,
              workflow: item.workflow,
              actorSlots: item.actorSlots,
              cleanupOnly: true
            }
          : {}),
        recoveryBundleAvailable: item.recoveryBundleAvailable
      }));
    const jobs = this.db.db
      .prepare(
        "SELECT j.id,j.case_id,j.status,j.created_at,j.target_id,j.checkpoint_digest FROM workflow_recovery_jobs j JOIN targets t ON t.id=j.target_id WHERE t.organization_id=? ORDER BY j.created_at DESC,j.id LIMIT 100"
      )
      .all(organizationId) as Row[];
    return {
      cases,
      jobs: jobs.map((j) => ({
        id: j.id, case_id: j.case_id, status: j.status, created_at: j.created_at,
        safe_summary: this.workflowJobSummary(j, organizationId)
      })),
      cleanupRequired: cases.length,
      attributionHold: inventory.cases.length !== cases.length,
      globalMutationActive: inventory.globalMutationActive
    };
  }
  /** Fixed, secret-free descriptions derived from bound immutable history, never stored free text. */
  private workflowJobSummary(job: Row, organizationId: string): string {
    const unknown = "Outcome UNKNOWN. Review immutable cleanup evidence; no automatic replay or authorization reuse.";
    try {
      return this.db.db.transaction(() => {
        const attempts = this.db.db.prepare("SELECT id FROM cleanup_attempts WHERE job_id=? LIMIT 2").all(job.id) as {id:string}[];
        if (!attempts.length) return job.status === "ROLLBACK_VERIFIED"
          ? "Stored cleanup restoration verified."
          : "Review the retained cleanup checkpoint and job state.";
        if (attempts.length !== 1) return unknown;
        const history = CleanupAttemptLedger.for(this.db).history(attempts[0]!.id), a = history.attempt,
          binding = JSON.parse(a.binding_json) as { checkpointDigest?: string };
        if (a.kind !== "WORKFLOW" || a.organization_id !== organizationId || a.target_id !== job.target_id ||
            a.case_id !== job.case_id || a.authority_key !== "workflow:" + job.checkpoint_digest ||
            (binding.checkpointDigest !== undefined && binding.checkpointDigest !== job.checkpoint_digest)) return unknown;
        if (history.phase === "UNKNOWN") return unknown;
        if (history.phase === "NOT_EXECUTED") return "No recovery command was granted. Restoration is not established; consumed authority cannot be reused.";
        if (history.phase === "RESTORATION_VERIFIED" && job.status === "ROLLBACK_VERIFIED") return "Stored cleanup restoration verified against immutable attempt evidence.";
        if (history.phase === "FAILED") return "Cleanup recovery failed. Restoration is not established; review retained evidence.";
        return unknown;
      })();
    } catch { return unknown; }
  }
  public originOwned(origin: string, organizationId: string): boolean {
    const rows = this.db.db.prepare("SELECT DISTINCT organization_id FROM targets WHERE base_origin=?").all(origin) as {
      organization_id: string;
    }[];
    return rows.length === 1 && rows[0]!.organization_id === organizationId;
  }

  public async snapshot(
    scope: RecoveryScope,
    dispatchState: string,
    options: {
      page?: number;
      pageSize?: number;
      kind?: string;
      subjectId?: string;
      ownedResourceIds?: readonly string[];
    } = {}
  ): Promise<RecoveryCenterSnapshot> {
    const page = options.page ?? 1,
      size = options.pageSize ?? 50;
    if (
      !Number.isSafeInteger(page) ||
      page < 1 ||
      page > 10000 ||
      !Number.isSafeInteger(size) ||
      size < 1 ||
      size > 100
    )
      throw new RecoveryOperationError(400, "Invalid recovery inventory page.");
    const issues: RecoveryIssue[] = [],
      warnings: string[] = [];
    let hasMore = false;
    const add = (
      kind: RecoveryIssue["kind"],
      row: Row,
      state: string,
      title: string,
      explanation: string,
      evidence: RecoveryIssue["evidence"],
      blocked: string[],
      actions = { cleanup: false, recompute: false }
    ) => {
      const subjectId = String(row.id),
        issue: RecoveryIssue = {
          kind,
          subjectId,
          state,
          title,
          explanation,
          snapshotDigest: sha({ kind, row: this.boundRow(kind, row) }),
          evidence,
          blockedActions: blocked,
          humanReviewRequired: true,
          actions: {
            review: scope.canReview && (kind !== "CUSTODY" || scope.canManageWorkers),
            recompute: scope.canRecompute && actions.recompute,
            cleanup: scope.canRecover && actions.cleanup
          }
        };
      const review = this.db.db
        .prepare(
          "SELECT decision,reason,created_at,snapshot_digest FROM operator_uncertainty_reviews WHERE organization_id=? AND kind=? AND subject_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1"
        )
        .get(scope.organizationId, kind, subjectId) as Row | undefined;
      if (review)
        issue.review = {
          decision: review.decision,
          reason: review.reason,
          createdAt: review.created_at,
          current: review.snapshot_digest === issue.snapshotDigest
        };
      issues.push(issue);
    };
    const rows = (kind: string, sql: string, args: unknown[] = []) => {
      if (options.kind && options.kind !== kind) return [];
      const values = [...args];
      let query = sql;
      if (options.subjectId) {
        query = `SELECT * FROM (${sql}) WHERE id=?`;
        values.push(options.subjectId);
      }
      query += " LIMIT ? OFFSET ?";
      values.push(size + 1, options.subjectId ? 0 : (page - 1) * size);
      const result = this.db.db.prepare(query).all(...values) as Row[];
      for (const row of result)
        this.snapshots.set(kind + ":" + row.id, () => {
          const fresh = this.db.db.prepare("SELECT * FROM (" + sql + ") WHERE id=?").get(...args, row.id) as
            Row | undefined;
          return fresh ? sha({ kind, row: this.boundRow(kind, fresh) }) : "";
        });
      hasMore ||= result.length > size;
      return result.slice(0, size);
    };
    for (const row of rows(
      "CUSTODY",
      `SELECT r.*,r.resource_id id FROM worker_resources r LEFT JOIN scans s ON s.id=r.job_id LEFT JOIN workflow_recovery_jobs j ON j.id=r.job_id LEFT JOIN targets t ON t.id=j.target_id LEFT JOIN controlled_mutation_approvals a ON a.recovery_job_id=r.job_id LEFT JOIN targets ct ON ct.id=a.target_id WHERE COALESCE(s.organization_id,t.organization_id,ct.organization_id)=? AND r.state IN ('UNKNOWN_RETAINED','CREATED','RUNNING','DRAINING') ORDER BY r.updated_at DESC,r.resource_id`,
      [scope.organizationId]
    )) {
      if (row.state !== "UNKNOWN_RETAINED" && options.ownedResourceIds?.includes(row.resource_id)) continue;
      row.id = row.resource_id;
      const evidence = parse(row.evidence_json ?? "{}"),
        custody = evidence.custody ?? {},
        job = custody.job ?? {};
      add(
        "CUSTODY",
        row,
        row.state,
        "Worker custody needs review",
        row.state === "UNKNOWN_RETAINED"
          ? "Native descendant custody is not proven. Root exit or a reviewed note cannot clear this uncertainty."
          : "Worker resources remain nonterminal. Check live worker diagnostics; historical rows cannot grant process ownership.",
        [
          { label: "Worker", value: row.worker_id },
          { label: "Job", value: row.job_id },
          { label: "Generation", value: row.generation },
          { label: "Retained evidence fingerprint", value: sha(row.evidence_json) },
          { label: "Root exit observed", value: custody.rootClosed === true ? "yes" : "not proven" },
          {
            label: "Native zero-membership acknowledgement",
            value: job.terminationAcknowledged === true ? "observed; does not erase other failures" : "not proven"
          },
          {
            label: "Root-only fallback",
            value: custody.rootOnlyFallback === true ? "yes; descendants remain uncertain" : "not reported"
          }
        ],
        [
          "Ordinary dispatch and fleet release remain subject to the custody fence.",
          "No historical PID termination, evidence deletion, automatic replay or custody reset is authorized."
        ]
      );
    }
    for (const row of rows(
      "ASSURANCE",
      `SELECT r.* FROM continuous_assurance_runs r JOIN continuous_assurance_policies p ON p.id=r.policy_id JOIN targets t ON t.id=p.target_id WHERE t.organization_id=? AND (r.gate_status<>'PASSED' OR r.status<>'COMPLETED') ORDER BY r.created_at DESC,r.id`,
      [scope.organizationId]
    )) {
      const summary = parse(row.safe_summary_json),
        unknown = summary.launchOutcome === "UNKNOWN" || summary.outcome === "UNKNOWN";
      const lanes = this.db.db
        .prepare(
          "SELECT l.status,l.scan_id,s.organization_id FROM continuous_assurance_run_scans l LEFT JOIN scans s ON s.id=l.scan_id WHERE l.run_id=? ORDER BY l.ordinal LIMIT 20"
        )
        .all(row.id) as Row[];
      const laneEvidence = lanes.flatMap((lane, index) => [
        {
          label: "Lane " + (index + 1),
          value: ["PENDING", "QUEUED", "COMPLETED", "FAILED", "BLOCKED", "CANCELLED"].includes(lane.status)
            ? lane.status
            : "UNKNOWN"
        },
        ...(lane.scan_id && lane.organization_id === scope.organizationId
          ? [{ label: "Scan", value: lane.scan_id }]
          : [])
      ]);
      add(
        "ASSURANCE",
        row,
        unknown ? "UNKNOWN" : row.gate_status,
        "Assurance outcome is not a verified pass",
        unknown
          ? "A submission or launch acknowledgement is uncertain. Replaying the run could repeat an action."
          : "A pending, blocked, incomplete or failing run cannot establish a healthy deployment gate.",
        [
          { label: "Run", value: row.id },
          { label: "Policy", value: row.policy_id },
          { label: "Execution status", value: row.status },
          { label: "Gate", value: row.gate_status },
          { label: "Summary fingerprint", value: sha(row.safe_summary_json) },
          ...laneEvidence
        ],
        [
          "No automatic resubmission or historical gate override.",
          "A human must review execution, cleanup and comparison evidence before any separately authorized new run."
        ]
      );
    }
    for (const row of rows(
      "DEPLOYMENT",
      `SELECT d.rowid id,p.id policy_id,d.deployment_id,d.build_fingerprint,d.received_at FROM continuous_assurance_deployments d JOIN continuous_assurance_policies p ON p.id=d.policy_id JOIN targets t ON t.id=p.target_id WHERE t.organization_id=? AND d.run_id IS NULL ORDER BY d.received_at DESC,d.policy_id,d.deployment_id`,
      [scope.organizationId]
    )) {
      add(
        "DEPLOYMENT",
        row,
        "UNKNOWN",
        "Deployment reservation has no bound run",
        "Reservation exists without a verified execution outcome. Absence of a run is not proof that no request was sent.",
        [
          { label: "Policy", value: row.policy_id },
          { label: "Build fingerprint", value: row.build_fingerprint },
          { label: "Reservation evidence fingerprint", value: sha(row) }
        ],
        [
          "Automatic replay and reservation reset remain blocked.",
          "Human investigation is required; acknowledging this item does not clear the reservation."
        ]
      );
    }
    for (const row of rows(
      "COMPARISON",
      `SELECT c.*,os.status older_status,ns.status newer_status FROM scan_comparisons c JOIN scans os ON os.id=c.older_scan_id JOIN scans ns ON ns.id=c.newer_scan_id WHERE os.organization_id=? AND ns.organization_id=? AND c.deleted_at IS NULL ORDER BY c.created_at DESC,c.id`,
      [scope.organizationId, scope.organizationId]
    )) {
      let reason = "COMPARISON_INCOMPLETE";
      try {
        assertComparisonSummary(JSON.parse(row.summary_json), row.id);
        assertAssuranceComparison(
          new ScanComparisonService(this.db).get(row.id),
          row.older_scan_id,
          row.newer_scan_id,
          []
        );
        continue;
      } catch (e) {
        if (e && typeof e === "object" && "reason" in e) reason = String(e.reason);
      }
      add(
        "COMPARISON",
        row,
        row.state,
        "Comparison evidence cannot establish a healthy gate",
        "Failed, malformed, partial or incomparable evidence must not be interpreted as zero findings or a passing assurance gate.",
        [
          { label: "Comparison", value: row.id },
          { label: "Diagnostic", value: reason },
          { label: "Older scan", value: row.older_scan_id },
          { label: "Newer scan", value: row.newer_scan_id },
          {
            label: "Source evidence fingerprint",
            value: sha([row.summary_json, row.coverage_summary_json, row.engine_version])
          }
        ],
        [
          "Historical assurance outcomes are not changed by recomputation.",
          "Original comparison evidence is retained; new analysis cannot repair missing scan coverage."
        ],
        {
          cleanup: false,
          recompute:
            ["COMPLETED", "IMPORTED"].includes(row.older_status) &&
            ["COMPLETED", "IMPORTED"].includes(row.newer_status) &&
            !["PENDING", "ANALYZING"].includes(row.state)
        }
      );
    }
    for (const row of rows(
      "CLEANUP",
      "SELECT 'approval:'||a.id id,a.id approval_id,a.case_id,a.target_id,a.target_origin,a.plan_identity,a.scope_digest,a.target_identity_fingerprint,a.status,a.expires_at,a.updated_at FROM controlled_mutation_approvals a JOIN targets t ON t.id=a.target_id WHERE t.organization_id=? AND a.status IN ('EXECUTING','CLEANUP_REQUIRED','CLEANUP_FAILED') ORDER BY a.updated_at DESC,a.id",
      [scope.organizationId]
    )) {
      let eligible = false;
      try {
        const inventory = await this.workflowInventory(scope.organizationId);
        eligible =
          !this.db.db.prepare("SELECT 1 FROM cleanup_attempts WHERE authority_key=?").get("approval:"+row.approval_id) &&
          row.status !== "EXECUTING" &&
          row.expires_at > new Date().toISOString() &&
          inventory.cases.some(
            (c) => c.caseId === row.case_id && c.recoveryKind === "CONTROLLED_CONTRACT" && c.recoveryBundleAvailable
          );
      } catch {
        /* No verifiable checkpoint: review only. */
      }
      add(
        "CLEANUP",
        row,
        row.status,
        "Controlled mutation cleanup remains unresolved",
        "Recovery requires the exact approval, target revision, scope and encrypted cleanup binding plus fresh credentials. No original mutation is replayed.",
        [
          { label: "Approval", value: row.approval_id },
          { label: "Case", value: row.case_id },
          { label: "Target", value: row.target_id },
          { label: "Plan fingerprint", value: row.plan_identity },
          { label: "Approval expires", value: row.expires_at }
        ],
        [
          "Cleanup cannot be cleared by review or fleet release.",
          row.status === "EXECUTING"
            ? "A cleanup or original operation is already executing; concurrent recovery is blocked."
            : row.expires_at <= new Date().toISOString()
              ? "Original recovery approval has expired. New authority cannot be issued by this workspace."
              : "Missing or changed cleanup material requires human investigation."
        ],
        { cleanup: eligible, recompute: false }
      );
    }
    if (!options.kind || options.kind === "CLEANUP") {
      try {
        const inventory = await this.workflowInventory(scope.organizationId);
        if (inventory.attributionHold)
          warnings.push(
            "Some cleanup obligations cannot be attributed exclusively to this organization. Details and recovery are withheld; installation owner review is required."
          );
        const cases = inventory.cases.filter(
          (c) => c.recoveryKind !== "CONTROLLED_CONTRACT" && (!options.subjectId || c.caseId === options.subjectId)
        );
        hasMore ||= cases.length > page * size;
        for (const c of cases.slice(options.subjectId ? 0 : (page - 1) * size, options.subjectId ? size : page * size))
          add(
            "CLEANUP",
            { ...c, id: c.caseId },
            c.stage,
            "Target restoration remains unresolved",
            "Only the sealed stored cleanup and verification steps may be recovered, with fresh target-bound credentials and explicit authorization.",
            [
              { label: "Case", value: c.caseId },
              { label: "Recovery contract", value: c.recoveryKind },
              { label: "Checkpoint", value: "checkpointDigest" in c ? String(c.checkpointDigest) : "unavailable" }
            ],
            [
              "New mutations remain blocked until verified restoration.",
              "Acknowledgement cannot release cleanup obligations or rerun attack steps."
            ],
            {
              cleanup:
                c.recoveryKind === "WORKFLOW" && "checkpointDigest" in c && typeof c.checkpointDigest === "string" && !this.db.db.prepare("SELECT 1 FROM cleanup_attempts WHERE authority_key=?").get("workflow:"+c.checkpointDigest),
              recompute: false
            }
          );
      } catch {
        warnings.push(
          "Cleanup inventory is unavailable. Recovery actions are blocked; an empty list is not proof of restoration."
        );
      }
    }
    for (const row of rows(
      "RECOVERY",
      `SELECT j.* FROM workflow_recovery_jobs j JOIN targets t ON t.id=j.target_id WHERE t.organization_id=? AND j.status<>'ROLLBACK_VERIFIED' ORDER BY j.created_at DESC,j.id`,
      [scope.organizationId]
    ))
      add(
        "RECOVERY",
        row,
        row.status,
        "Cleanup recovery needs attention",
        "A queued, interrupted or failing cleanup job has not established verified restoration.",
        [
          { label: "Recovery job", value: row.id },
          { label: "Case", value: row.case_id },
          { label: "Checkpoint", value: row.checkpoint_digest }
        ],
        [
          "Failed recovery is not a successful rollback.",
          "Inspect the current obligation and supply fresh credentials before a separately authorized retry."
        ]
      );

    for(const row of rows("RECOVERY",`SELECT a.job_id,a.organization_id,a.target_id,a.case_id,a.kind,a.authority_key,a.request_key,a.binding_json,a.binding_digest,a.requested_by,a.controller_id,a.created_at,a.id attempt_id,'attempt:'||a.id id,e.kind phase,e.event_hash head FROM cleanup_attempts a JOIN cleanup_attempt_events e ON e.attempt_id=a.id AND e.sequence=(SELECT MAX(sequence) FROM cleanup_attempt_events WHERE attempt_id=a.id) WHERE a.organization_id=? ORDER BY a.created_at DESC,a.id`,[scope.organizationId])){
      const history=CleanupAttemptLedger.for(this.db).history(row.attempt_id);
      add("RECOVERY",row,row.phase,"Cleanup attempt lifecycle",row.phase==="RESTORATION_VERIFIED"?"This attempt has independently checked journal proof and drained native worker custody. Earlier failed and uncertain attempts remain retained.":row.phase==="NOT_EXECUTED"?"No recovery command was granted and any owned worker custody is retained. This is not restoration; the consumed authority cannot be reused.":"Inspect the immutable attempt timeline. An acknowledgement, request or worker result is not independently verified restoration.",[{label:"Attempt",value:row.attempt_id},{label:"Case",value:row.case_id},{label:"Recovery job",value:row.job_id},{label:"Immutable binding",value:row.binding_digest},{label:"History head",value:history.head}],["No automatic replay or reuse of this consumed authority.",row.phase==="UNKNOWN"?"Potential execution or native custody is unresolved; dispatch and release remain quarantined.":"A separately authorized next action requires intact target, checkpoint and custody bindings."]);
      const issue=issues.at(-1)!;if(row.phase==="RESTORATION_VERIFIED"){issue.humanReviewRequired=false;issue.actions.review=false;}
    }
    return {
      schemaVersion: 1,
      organizationId: scope.organizationId,
      automaticReplay: false,
      dispatchState,
      issues,
      inventoryWarnings: warnings,
      hasMore,
      page,
      pageSize: size
    };
  }

  public async recompute(scope: RecoveryScope, input: unknown) {
    const v = recoveryRecomputeSchema.parse(input);
    if (!scope.canRecompute) throw new RecoveryOperationError(403, "Comparison recompute permission required.");
    const issue = (await this.snapshot(scope, "UNKNOWN", { kind: "COMPARISON", subjectId: v.subjectId })).issues[0];
    if (!issue) throw new RecoveryOperationError(404, "Comparison evidence is unavailable in this organization.");
    if (!issue.actions.recompute)
      throw new RecoveryOperationError(
        409,
        "Original scans must be terminal; active comparisons cannot be recomputed."
      );
    return this.db.transaction(() => {
      const prior = this.db.db
        .prepare("SELECT * FROM operator_comparison_attempts WHERE organization_id=? AND request_id=?")
        .get(scope.organizationId, v.requestId) as Row | undefined;
      if (prior) {
        if (
          prior.subject_id !== v.subjectId ||
          prior.snapshot_digest !== v.snapshotDigest ||
          prior.requested_by !== scope.actor
        )
          throw new RecoveryOperationError(409, "Comparison request identity changed.");
        return {
          attemptId: prior.id,
          status: prior.status,
          comparisonId: prior.result_comparison_id,
          historicalGateChanged: false,
          replayed: false
        };
      }
      if (
        issue.snapshotDigest !== v.snapshotDigest ||
        this.snapshots.get("COMPARISON:" + v.subjectId)?.() !== v.snapshotDigest
      )
        throw new RecoveryOperationError(409, "Comparison evidence changed. Refresh before recomputing.");
      const source = this.db.db
        .prepare("SELECT older_scan_id,newer_scan_id FROM scan_comparisons WHERE id=?")
        .get(v.subjectId) as Row;
      const before = (
        this.db.db.prepare("SELECT COALESCE(MAX(rowid),0) n FROM scan_comparisons").get() as { n: number }
      ).n;
      const id = randomUUID(),
        now = new Date().toISOString();
      let status = "COMPLETED";
      try {
        new ScanComparisonService(this.db).compare(source.older_scan_id, source.newer_scan_id, {
          recompute: true,
          createdByUserId: scope.actor
        });
      } catch {
        status = "FAILED";
      }
      const result = this.db.db
        .prepare(
          "SELECT id FROM scan_comparisons WHERE rowid>? AND older_scan_id=? AND newer_scan_id=? ORDER BY rowid DESC LIMIT 1"
        )
        .get(before, source.older_scan_id, source.newer_scan_id) as { id: string } | undefined;
      if (result)
        this.db.db
          .prepare("UPDATE scan_comparisons SET supersedes_comparison_id=? WHERE id=?")
          .run(v.subjectId, result.id);
      this.db.db
        .prepare(
          "INSERT INTO operator_comparison_attempts(id,organization_id,subject_id,snapshot_digest,request_id,requested_by,status,result_comparison_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)"
        )
        .run(
          id,
          scope.organizationId,
          v.subjectId,
          v.snapshotDigest,
          v.requestId,
          scope.actor,
          status,
          result?.id ?? null,
          now
        );
      new AuditRepository(this.db).append({
        actorLabel: scope.actor,
        action: "RECOVERY_COMPARISON_ATTEMPT",
        resourceType: "RECOVERY_COMPARISON",
        resourceId: id,
        summary: "New offline comparison attempt retained; original evidence and assurance gates unchanged.",
        metadata: { subjectId: v.subjectId, status, comparisonId: result?.id ?? null }
      });
      return { attemptId: id, status, comparisonId: result?.id ?? null, historicalGateChanged: false, replayed: false };
    });
  }

  public async review(scope: RecoveryScope, input: unknown) {
    const v = recoveryReviewSchema.parse(input),
      snapshot = await this.snapshot(scope, "UNKNOWN", { kind: v.kind, subjectId: v.subjectId }),
      issue = snapshot.issues.find((i) => i.subjectId === v.subjectId);
    if (!issue) throw new RecoveryOperationError(404, "Recovery evidence is not available in this organization.");
    if (!issue.actions.review) throw new RecoveryOperationError(403, "Permission required to review this uncertainty.");
    if (issue.snapshotDigest !== v.snapshotDigest)
      throw new RecoveryOperationError(409, "Recovery evidence changed. Refresh before review.");
    return this.db.transaction(() => {
      const current = this.snapshots.get(v.kind + ":" + v.subjectId);
      if (current && current() !== v.snapshotDigest)
        throw new RecoveryOperationError(409, "Recovery evidence changed. Refresh before review.");
      const id = randomUUID(),
        now = new Date().toISOString();
      this.db.db
        .prepare(
          "INSERT OR IGNORE INTO operator_uncertainty_reviews(id,organization_id,kind,subject_id,snapshot_digest,reviewer,decision,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)"
        )
        .run(id, scope.organizationId, v.kind, v.subjectId, v.snapshotDigest, scope.actor, v.decision, v.reason, now);
      const row = this.db.db
        .prepare(
          "SELECT id FROM operator_uncertainty_reviews WHERE organization_id=? AND kind=? AND subject_id=? AND snapshot_digest=? AND reviewer=? AND decision=?"
        )
        .get(scope.organizationId, v.kind, v.subjectId, v.snapshotDigest, scope.actor, v.decision) as { id: string };
      if (row.id === id)
        new AuditRepository(this.db).append({
          actorLabel: scope.actor,
          action: "UNCERTAINTY_REVIEW_RECORDED",
          resourceType: "RECOVERY_REVIEW",
          resourceId: id,
          summary: "Evidence reviewed without clearing custody, cleanup, reservations or assurance gates.",
          metadata: { kind: v.kind, subjectId: v.subjectId, snapshotDigest: v.snapshotDigest, decision: v.decision }
        });
      return { reviewId: row.id, uncertaintyResolved: false, executionAuthorized: false };
    });
  }
}
