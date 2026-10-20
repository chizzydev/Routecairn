import { createHash, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
export const cleanupDigest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export type CleanupPhase =
  | "REQUESTED"
  | "AUTHORIZED"
  | "WORKER_PENDING"
  | "WORKER_ACTIVATED"
  | "DISPATCH_ARMED"
  | "DISPATCH_ATTEMPTED"
  | "RESULT_RECEIVED"
  | "RESTORATION_VERIFIED"
  | "FAILED"
  | "UNKNOWN"
  | "NOT_EXECUTED";
export interface CleanupAttempt {
  id: string;
  job_id: string;
  organization_id: string;
  target_id: string;
  case_id: string;
  kind: "WORKFLOW" | "CONTROLLED";
  authority_key: string;
  request_key: string;
  binding_json: string;
  binding_digest: string;
  requested_by: string;
  controller_id: string;
  created_at: string;
}
export interface CleanupEvent {
  attempt_id: string;
  sequence: number;
  kind: CleanupPhase;
  evidence_json: string;
  previous_hash: string;
  event_hash: string;
  created_at: string;
}
const terminal = new Set<CleanupPhase>(["RESTORATION_VERIFIED", "FAILED", "UNKNOWN", "NOT_EXECUTED"]),
  instances = new WeakMap<DashboardDatabase, CleanupAttemptLedger>();
const transitions: Record<string, readonly CleanupPhase[]> = {
  REQUESTED: ["AUTHORIZED"],
  AUTHORIZED: ["WORKER_PENDING", "NOT_EXECUTED", "UNKNOWN"],
  WORKER_PENDING: ["WORKER_ACTIVATED", "NOT_EXECUTED", "UNKNOWN"],
  WORKER_ACTIVATED: ["DISPATCH_ARMED", "NOT_EXECUTED", "UNKNOWN"],
  DISPATCH_ARMED: ["DISPATCH_ATTEMPTED", "UNKNOWN"],
  DISPATCH_ATTEMPTED: ["DISPATCH_ATTEMPTED", "RESULT_RECEIVED", "UNKNOWN"],
  RESULT_RECEIVED: ["RESTORATION_VERIFIED", "FAILED", "UNKNOWN"]
};
export class CleanupAttemptLedger {
  public readonly controllerId = randomUUID();
  public static for(db: DashboardDatabase) {
    let value = instances.get(db);
    if (!value) {
      value = new CleanupAttemptLedger(db);
      instances.set(db, value);
    }
    return value;
  }
  public constructor(private readonly db: DashboardDatabase) {
    if (Number(db.db.pragma("synchronous", { simple: true })) < 2) throw Error("RECOVERY_DURABILITY_REQUIRED");
  }
  public get(id: string) {
    return this.db.db.prepare("SELECT * FROM cleanup_attempts WHERE id=?").get(id) as CleanupAttempt | undefined;
  }
  public history(id: string) {
    const a = this.get(id);
    if (!a) throw Error("RECOVERY_ATTEMPT_NOT_FOUND");
    const events = this.db.db
      .prepare("SELECT * FROM cleanup_attempt_events WHERE attempt_id=? ORDER BY sequence")
      .all(id) as CleanupEvent[];
    let prior = a.binding_digest,
      phase: CleanupPhase | undefined;
    for (let i = 0; i < events.length; i++) {
      const e = events[i]!,
        { event_hash, ...body } = e;
      if (
        e.sequence !== i + 1 ||
        e.previous_hash !== prior ||
        cleanupDigest(body) !== event_hash ||
        (phase && (!transitions[phase]?.includes(e.kind) || terminal.has(phase)))
      )
        throw Error("RECOVERY_ATTEMPT_INTEGRITY_FAILED");
      prior = e.event_hash;
      phase = e.kind;
    }
    if (
      !events.length ||
      events[0]!.kind !== "REQUESTED" ||
      cleanupDigest(JSON.parse(a.binding_json)) !== a.binding_digest
    )
      throw Error("RECOVERY_ATTEMPT_INTEGRITY_FAILED");
    return { attempt: a, events, phase: phase!, head: prior };
  }
  public lookup(requestId: string | undefined, organizationId: string, actor: string, submissionDigest: string) {
    if (!requestId) return undefined;
    const row = this.db.db
      .prepare("SELECT * FROM cleanup_attempts WHERE organization_id=? AND request_key=?")
      .get(organizationId, requestId) as CleanupAttempt | undefined;
    if (!row) return undefined;
    if (row.requested_by !== actor || JSON.parse(row.binding_json).submissionDigest !== submissionDigest)
      throw Error("RECOVERY_REQUEST_IDENTITY_CHANGED");
    this.history(row.id);
    return row;
  }
  public reserve(
    input: {
      jobId: string;
      organizationId: string;
      targetId: string;
      caseId: string;
      kind: "WORKFLOW" | "CONTROLLED";
      authorityKey: string;
      requestId?: string;
      requestedBy: string;
      binding: Record<string, unknown>;
    },
    authorize: () => void
  ) {
    if (Number(this.db.db.pragma("synchronous", { simple: true })) < 2) throw Error("RECOVERY_DURABILITY_REQUIRED");
    return this.db.db
      .transaction(() => {
        const binding = JSON.stringify(input.binding),
          digest = cleanupDigest(input.binding),
          requestKey = input.requestId ?? "legacy:" + cleanupDigest([input.kind, input.authorityKey]);
        const prior = this.db.db
          .prepare("SELECT * FROM cleanup_attempts WHERE organization_id=? AND request_key=?")
          .get(input.organizationId, requestKey) as CleanupAttempt | undefined;
        if (prior) {
          if (!input.requestId) throw Error("RECOVERY_AUTHORITY_ALREADY_CONSUMED");
          if (
            JSON.parse(prior.binding_json).submissionDigest !== input.binding.submissionDigest ||
            prior.requested_by !== input.requestedBy ||
            prior.authority_key !== input.authorityKey
          )
            throw Error("RECOVERY_REQUEST_IDENTITY_CHANGED");
          this.history(prior.id);
          return { attempt: prior, replayed: true };
        }
        if (this.db.db.prepare("SELECT 1 FROM cleanup_attempts WHERE authority_key=?").get(input.authorityKey))
          throw Error("RECOVERY_AUTHORITY_ALREADY_CONSUMED");
        const blocked = this.db.db
          .prepare(
            "SELECT a.id,e.kind FROM cleanup_attempts a JOIN cleanup_attempt_events e ON e.attempt_id=a.id AND e.sequence=(SELECT MAX(sequence) FROM cleanup_attempt_events WHERE attempt_id=a.id) WHERE a.target_id=? AND a.case_id=? AND e.kind NOT IN ('RESTORATION_VERIFIED','NOT_EXECUTED') LIMIT 1"
          )
          .get(input.targetId, input.caseId);
        if (blocked) throw Error("RECOVERY_PRIOR_ATTEMPT_UNRESOLVED");
        const id = randomUUID(),
          now = new Date().toISOString();
        this.db.db
          .prepare("INSERT INTO cleanup_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
          .run(
            id,
            input.jobId,
            input.organizationId,
            input.targetId,
            input.caseId,
            input.kind,
            input.authorityKey,
            requestKey,
            binding,
            digest,
            input.requestedBy,
            this.controllerId,
            now
          );
        this.append(id, "REQUESTED", {});
        authorize();
        this.append(id, "AUTHORIZED", {});
        return { attempt: this.get(id)!, replayed: false };
      })
      .immediate();
  }
  public append(id: string, kind: CleanupPhase, evidence: Record<string, unknown>) {
    if (Number(this.db.db.pragma("synchronous", { simple: true })) < 2) throw Error("RECOVERY_DURABILITY_REQUIRED");
    return this.db.db.transaction(() => {
      const a = this.get(id);
      if (!a) throw Error("RECOVERY_ATTEMPT_NOT_FOUND");
      const rows = this.db.db
        .prepare("SELECT * FROM cleanup_attempt_events WHERE attempt_id=? ORDER BY sequence")
        .all(id) as CleanupEvent[];
      if (rows.length) {
        const state = this.history(id);
        if (terminal.has(state.phase) || !transitions[state.phase]?.includes(kind))
          throw Error("RECOVERY_ATTEMPT_TRANSITION_REFUSED");
      } else if (kind !== "REQUESTED") throw Error("RECOVERY_ATTEMPT_TRANSITION_REFUSED");
      const last = rows.at(-1),
        body = {
          attempt_id: id,
          sequence: rows.length + 1,
          kind,
          evidence_json: JSON.stringify(evidence),
          previous_hash: last?.event_hash ?? a.binding_digest,
          created_at: new Date().toISOString()
        },
        hash = cleanupDigest(body);
      this.db.db
        .prepare(
          "INSERT INTO cleanup_attempt_events(attempt_id,sequence,kind,evidence_json,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?)"
        )
        .run(id, body.sequence, kind, body.evidence_json, body.previous_hash, hash, body.created_at);
      return hash;
    })();
  }
  public owns(id: string) {
    if (this.get(id)?.controller_id !== this.controllerId) throw Error("RECOVERY_CONTROLLER_MISMATCH");
  }
  public gate(id: string, ordinal: number) {
    this.owns(id);
    const h = this.history(id),
      last = h.events.filter((e) => e.kind === "DISPATCH_ATTEMPTED").length;
    if (ordinal !== last + 1 || ordinal > 10000) throw Error("RECOVERY_DISPATCH_SEQUENCE_REFUSED");
    return this.append(id, "DISPATCH_ATTEMPTED", { ordinal, transmission: "MAY_BE_EXECUTED_AFTER_ACK" });
  }
  public unresolved() {
    for (const row of this.db.db.prepare("SELECT id FROM cleanup_attempts").iterate() as Iterable<{ id: string }>) {
      try {
        if (["DISPATCH_ARMED", "DISPATCH_ATTEMPTED", "RESULT_RECEIVED", "UNKNOWN"].includes(this.history(row.id).phase))
          return true;
      } catch {
        return true;
      }
    }
    return false;
  }
  public interrupt(id: string) {
    const h = this.history(id);
    if (terminal.has(h.phase)) return;
    const resources = this.db.db.prepare("SELECT state FROM worker_resources WHERE job_id=?").all(h.attempt.job_id) as {
      state: string;
    }[];
    const pre = !h.events.some((e) => e.kind === "DISPATCH_ARMED"),
      known = resources.every((r) => r.state === "RETAINED");
    this.append(id, pre && known ? "NOT_EXECUTED" : "UNKNOWN", {
      reason: pre && known ? "NO_RECOVERY_COMMAND_GRANTED" : "EXECUTION_OR_CUSTODY_UNPROVEN",
      automaticReplay: false
    });
  }
  /** Synchronous ledger/projection commit: never hold a write transaction while draining a worker. */
  public interruptAndProject(id: string): void {
    if (Number(this.db.db.pragma("synchronous", { simple: true })) < 2) throw Error("RECOVERY_DURABILITY_REQUIRED");
    this.db.db
      .transaction(() => {
        this.interrupt(id);
        this.projectInterruptedCompatibility(id);
      })
      .immediate();
  }

  /** Repair only stale active summaries. Immutable terminal history and quarantine stay authoritative. */
  private projectInterruptedCompatibility(id: string): void {
    const history = this.history(id);
    if (history.phase !== "UNKNOWN" && history.phase !== "NOT_EXECUTED") return;
    const a = history.attempt,
      binding = JSON.parse(a.binding_json) as { approvalId?: string; checkpointDigest?: string },
      at = history.events.at(-1)!.created_at,
      error = history.phase === "UNKNOWN" ? "RECOVERY_OUTCOME_UNKNOWN" : "RECOVERY_NOT_EXECUTED";
    if (a.kind === "CONTROLLED") {
      const rows = this.db.db
        .prepare(
          "SELECT p.*,t.organization_id FROM controlled_mutation_approvals p JOIN targets t ON t.id=p.target_id WHERE p.recovery_job_id=?"
        )
        .all(a.job_id) as Array<{
        id: string;
        case_id: string;
        target_id: string;
        organization_id: string;
        status: string;
      }>;
      // Evidence-only/legacy histories do not authorize creation or adoption of an absent approval.
      if (!rows.length) return;
      const row = rows[0]!;
      if (
        rows.length !== 1 ||
        row.case_id !== a.case_id ||
        row.target_id !== a.target_id ||
        row.organization_id !== a.organization_id ||
        a.authority_key !== "approval:" + row.id ||
        (binding.approvalId !== undefined && binding.approvalId !== row.id)
      )
        throw Error("RECOVERY_COMPATIBILITY_BINDING_INVALID");
      if (row.status !== "EXECUTING") return;
      const result = this.db.db
        .prepare(
          "UPDATE controlled_mutation_approvals SET status='CLEANUP_FAILED',recovery_completed_at=COALESCE(recovery_completed_at,?),recovery_error_summary=?,updated_at=? WHERE id=? AND recovery_job_id=? AND status='EXECUTING'"
        )
        .run(at, error, at, row.id, a.job_id);
      if (result.changes !== 1) throw Error("RECOVERY_COMPATIBILITY_STATE_CONFLICT");
    } else {
      const row = this.db.db
        .prepare(
          "SELECT j.*,t.organization_id FROM workflow_recovery_jobs j JOIN targets t ON t.id=j.target_id WHERE j.id=?"
        )
        .get(a.job_id) as
        | { case_id: string; checkpoint_digest: string; target_id: string; organization_id: string; status: string }
        | undefined;
      if (!row) return;
      if (
        row.case_id !== a.case_id ||
        row.target_id !== a.target_id ||
        row.organization_id !== a.organization_id ||
        a.authority_key !== "workflow:" + row.checkpoint_digest ||
        (binding.checkpointDigest !== undefined && binding.checkpointDigest !== row.checkpoint_digest)
      )
        throw Error("RECOVERY_COMPATIBILITY_BINDING_INVALID");
      if (row.status !== "RUNNING") return;
      const summary =
        history.phase === "UNKNOWN"
          ? "Outcome UNKNOWN. No automatic replay or authorization reuse."
          : "No recovery command was granted. Restoration is not established; consumed authority cannot be reused.";
      const result = this.db.db
        .prepare(
          "UPDATE workflow_recovery_jobs SET status='CLEANUP_FAILED',completed_at=COALESCE(completed_at,?),safe_summary=? WHERE id=? AND status='RUNNING'"
        )
        .run(at, summary, a.job_id);
      if (result.changes !== 1) throw Error("RECOVERY_COMPATIBILITY_STATE_CONFLICT");
    }
  }
  /** Called once under the dashboard singleton, before any new recovery is accepted. */
  public reconcileStartup() {
    this.db.db
      .prepare(
        "UPDATE workflow_recovery_jobs SET status='INTERRUPTED',completed_at=?,safe_summary='Legacy job interrupted; no attempt history can be reconstructed and no replay is authorized.' WHERE status='RUNNING' AND NOT EXISTS(SELECT 1 FROM cleanup_attempts a WHERE a.job_id=workflow_recovery_jobs.id)"
      )
      .run(new Date().toISOString());
    const attempts = this.db.db
      .prepare("SELECT id FROM cleanup_attempts WHERE controller_id<>? ORDER BY created_at,id")
      .all(this.controllerId) as { id: string }[];
    for (const a of attempts) this.interruptAndProject(a.id);
  }
}
