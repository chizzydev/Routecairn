import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "./DashboardDatabase.js";
import { clamp, nowIso } from "./DashboardDatabase.js";

export type ControlledMutationApprovalStatus = "PREVIEWED" | "APPROVED" | "EXECUTING" | "COMPLETED" | "CLEANUP_REQUIRED" | "CLEANUP_FAILED" | "REJECTED" | "EXPIRED";
export interface ControlledMutationApprovalSummary { id: string; caseId: string; targetId: string; targetOrigin: string; targetIdentityFingerprint: string; scopeDigest: string; planIdentity: string; recoveryJobId?: string; recoveryStartedAt?: string; recoveryCompletedAt?: string; recoveryErrorSummary?: string; authorizationSummary: string; expiresAt: string; status: ControlledMutationApprovalStatus; approvedBy?: string; approvedAt?: string; createdAt: string; updatedAt: string; }

export class ControlledMutationApprovalRepository {
  public constructor(private readonly database: DashboardDatabase) {}
  public create(input: { caseId: string; targetId: string; targetOrigin: string; targetIdentityFingerprint: string; scopeDigest: string; planIdentity: string; authorizationSummary: string; expiresAt: string }): string {
    const id = randomUUID(); const now = nowIso();
    this.database.db.prepare("INSERT INTO controlled_mutation_approvals (id, case_id, target_id, target_origin, target_identity_fingerprint, scope_digest, plan_identity, authorization_summary, expires_at, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREVIEWED', ?, ?)").run(id, input.caseId, input.targetId, input.targetOrigin, input.targetIdentityFingerprint, input.scopeDigest, input.planIdentity, clamp(input.authorizationSummary, 1000), input.expiresAt, now, now);
    return id;
  }
  public get(id: string): ControlledMutationApprovalSummary | undefined { const row = this.database.db.prepare("SELECT * FROM controlled_mutation_approvals WHERE id = ?").get(id) as ApprovalRow | undefined; return row ? fromRow(row) : undefined; }
  public getByRecoveryJob(recoveryJobId: string): ControlledMutationApprovalSummary | undefined { const row = this.database.db.prepare("SELECT * FROM controlled_mutation_approvals WHERE recovery_job_id = ?").get(recoveryJobId) as ApprovalRow | undefined; return row ? fromRow(row) : undefined; }
  public approve(id: string, approvedBy: string): ControlledMutationApprovalSummary {
    const now = nowIso(); const result = this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = 'APPROVED', approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ? AND status = 'PREVIEWED' AND expires_at > ?").run(approvedBy, now, now, id, now);
    if (result.changes !== 1) throw new Error("MUTATION_APPROVAL_UNAVAILABLE: Approval is expired, already approved, or unavailable.");
    return this.get(id)!;
  }
  public beginRecovery(id: string, recoveryJobId: string): ControlledMutationApprovalSummary {
    const now = nowIso(); const result = this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = 'EXECUTING', recovery_job_id = ?, recovery_started_at = ?, recovery_error_summary = NULL, updated_at = ? WHERE id = ? AND status IN ('APPROVED','CLEANUP_REQUIRED','CLEANUP_FAILED') AND expires_at > ?").run(recoveryJobId, now, now, id, now);
    if (result.changes !== 1) throw new Error("MUTATION_RECOVERY_UNAVAILABLE: Approval is not available for exactly one recovery operation.");
    return this.get(id)!;
  }
  /** Consumed transactionally with scan creation; an approval cannot enqueue twice. */
  public beginExecution(id: string, scanId: string): void {
    const now = nowIso();
    const result = this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = 'EXECUTING', execution_scan_id = ?, updated_at = ? WHERE id = ? AND status = 'APPROVED' AND execution_scan_id IS NULL AND expires_at > ?").run(scanId, now, id, now);
    if (result.changes !== 1) throw new Error("MUTATION_EXECUTION_UNAVAILABLE: Approval was consumed, expired, or unavailable.");
  }
  public finishExecution(scanId: string, cleanupUnresolved: boolean): void {
    this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = ?, updated_at = ? WHERE execution_scan_id = ? AND status = 'EXECUTING'").run(cleanupUnresolved ? "CLEANUP_REQUIRED" : "COMPLETED", nowIso(), scanId);
  }
  public recoverInterruptedExecutions(): void {
    this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = 'CLEANUP_REQUIRED', updated_at = ? WHERE status = 'EXECUTING' AND execution_scan_id IN (SELECT id FROM scans WHERE status IN ('FAILED','INTERRUPTED','CANCELLED'))").run(nowIso());
  }
  public updateStatus(id: string, status: ControlledMutationApprovalStatus, errorSummary?: string): void { const completed = status === "COMPLETED" || status === "CLEANUP_FAILED" ? nowIso() : null; const result = this.database.db.prepare("UPDATE controlled_mutation_approvals SET status = ?, recovery_completed_at = COALESCE(?, recovery_completed_at), recovery_error_summary = ?, updated_at = ? WHERE id = ? AND status IN ('EXECUTING','APPROVED')").run(status, completed, errorSummary ? clamp(errorSummary, 800) : null, nowIso(), id); if (result.changes !== 1) throw new Error("MUTATION_RECOVERY_STATE_CONFLICT: Recovery status transition was not applied."); }
}
interface ApprovalRow { id: string; case_id: string; target_id: string; target_origin: string; target_identity_fingerprint: string; scope_digest: string; plan_identity: string; recovery_job_id: string | null; recovery_started_at: string | null; recovery_completed_at: string | null; recovery_error_summary: string | null; authorization_summary: string; expires_at: string; status: ControlledMutationApprovalStatus; approved_by: string | null; approved_at: string | null; created_at: string; updated_at: string; }
function fromRow(row: ApprovalRow): ControlledMutationApprovalSummary { return { id: row.id, caseId: row.case_id, targetId: row.target_id, targetOrigin: row.target_origin, targetIdentityFingerprint: row.target_identity_fingerprint, scopeDigest: row.scope_digest, planIdentity: row.plan_identity, ...(row.recovery_job_id ? { recoveryJobId: row.recovery_job_id } : {}), ...(row.recovery_started_at ? { recoveryStartedAt: row.recovery_started_at } : {}), ...(row.recovery_completed_at ? { recoveryCompletedAt: row.recovery_completed_at } : {}), ...(row.recovery_error_summary ? { recoveryErrorSummary: row.recovery_error_summary } : {}), authorizationSummary: row.authorization_summary, expiresAt: row.expires_at, status: row.status, ...(row.approved_by ? { approvedBy: row.approved_by } : {}), ...(row.approved_at ? { approvedAt: row.approved_at } : {}), createdAt: row.created_at, updatedAt: row.updated_at }; }
