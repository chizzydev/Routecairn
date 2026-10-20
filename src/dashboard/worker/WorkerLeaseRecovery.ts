import { randomUUID } from "node:crypto";
import { OwnedTemporaryResource } from "../../core/storage/OwnedTemporaryResource.js";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";
import { nowIso, type DashboardDatabase } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { windowsProcessBirth } from "./WindowsProcessIdentity.js";
import { WorkerGovernanceRepository } from "./WorkerGovernance.js";

interface ExpiredLease { kind: "scan" | "recovery"; job_id: string; worker_id: string; expires_at: string; process_id: number | null; process_identity_json: string | null; }
function alive(pid: number): boolean { try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code !== "ESRCH"; } }
function table(row: ExpiredLease): string { return row.kind === "scan" ? "scan_job_leases" : "controlled_mutation_recovery_leases"; }

/** Reconcile metadata only. Durable receipts are evidence, never live capabilities.
 * No process signaling, old-directory writes, deletion, adoption or automatic replay. */
export async function recoverWorkerLeases(database: DashboardDatabase, paths: DashboardPaths): Promise<string[]> {
  const rows = database.db.prepare(`
    SELECT 'scan' kind, leases.job_id, leases.worker_id, leases.expires_at, workers.process_id, resources.process_identity_json
    FROM scan_job_leases leases LEFT JOIN scan_workers workers ON workers.id = leases.worker_id LEFT JOIN worker_resources resources ON resources.worker_id = leases.worker_id
    WHERE leases.released_at IS NULL AND leases.expires_at < ?
    UNION ALL
    SELECT 'recovery' kind, leases.job_id, leases.worker_id, leases.expires_at, workers.process_id, resources.process_identity_json
    FROM controlled_mutation_recovery_leases leases LEFT JOIN scan_workers workers ON workers.id = leases.worker_id LEFT JOIN worker_resources resources ON resources.worker_id = leases.worker_id
    WHERE leases.released_at IS NULL AND leases.expires_at < ?`).all(nowIso(), nowIso()) as ExpiredLease[];
  const recovered = new Set<string>();
  const hold = (row: ExpiredLease, reason: string) => {
    const metadata = JSON.stringify({ workerId: row.worker_id, leaseKind: row.kind, reason, processAdopted: false, deletionAuthorized: false });
    if (!database.db.prepare("SELECT 1 FROM scan_events WHERE scan_id = ? AND event_type = 'WORKER_RECOVERY_HELD' AND safe_metadata_json = ?").get(row.job_id, metadata)) {
      database.db.prepare("INSERT INTO scan_events (id, seq, scan_id, event_type, safe_message, safe_metadata_json, created_at) SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, 'WORKER_RECOVERY_HELD', ?, ?, ? FROM scan_events WHERE scan_id = ?").run(randomUUID(), row.job_id, "Worker recovery is held; process custody or restoration is unresolved.", metadata, nowIso(), row.job_id);
    }
  };
  for (const row of rows) {
    if (!Number.isFinite(Date.parse(row.expires_at))) { hold(row, "LEASE_TIMESTAMP_INVALID"); continue; }
    // A lost manager may leave a cleanup-capable kernel-job custodian alive even
    // after the root exits. Never ingest evidence during that restoration window.
    if (Date.now() < Date.parse(row.expires_at) + workerRestorationGraceMs) { hold(row, "RESTORATION_GRACE"); continue; }
    if (row.process_id && alive(row.process_id)) {
      let expected: { pid: number; birth: string };
      try {
        const value: unknown = JSON.parse(row.process_identity_json ?? "null");
        if (!value || typeof value !== "object" || !("pid" in value) || value.pid !== row.process_id || !("birth" in value) || typeof value.birth !== "string" || !/^\d{16,20}$/.test(value.birth)) throw Error("IDENTITY_INVALID");
        expected = value as typeof expected;
      } catch { hold(row, "PROCESS_IDENTITY_UNKNOWN"); continue; }
      if (process.platform !== "win32") { hold(row, "PLATFORM_NOT_VERIFIED"); continue; }
      const observation = OwnedTemporaryResource.create(paths.workersDir, { purpose: "lease-observation", workerId: row.worker_id, jobId: row.job_id });
      let observed: string | null | undefined;
      try { observed = await windowsProcessBirth(row.process_id, observation.directory("tmp")); }
      catch { observed = undefined; }
      finally { observation.retain("READ_ONLY_PROCESS_OBSERVATION"); }
      if (observed === undefined || observed === expected.birth) { hold(row, observed === undefined ? "PROCESS_OBSERVATION_UNKNOWN" : "MATCHING_PROCESS_STILL_ALIVE"); continue; }
    }
    const current = database.db.prepare(`SELECT worker_id FROM ${table(row)} WHERE job_id = ? AND released_at IS NULL AND expires_at >= ? AND worker_id <> ?`).get(row.job_id, nowIso(), row.worker_id);
    if (current) {
      database.db.prepare(`UPDATE ${table(row)} SET released_at = ?, release_category = 'EXPIRED_SUPERSEDED' WHERE job_id = ? AND worker_id = ? AND released_at IS NULL`).run(nowIso(), row.job_id, row.worker_id);
      continue;
    }
    const cleanup = await readMutationCleanupStatus(paths.mutationJournalDir, paths.mutationJournalRegistryPath).catch(() => undefined);
    const cleanupRequired = row.kind === "recovery" || !cleanup || cleanup.cleanupRequired > 0;
    database.transaction(() => {
      database.db.prepare("UPDATE scans SET status = 'INTERRUPTED', completed_at = ?, error_summary = ? WHERE id = ? AND status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED')").run(nowIso(), cleanupRequired ? "Worker lease expired; cleanup outcome remains unresolved. Operator recovery is required." : "Worker lease expired before a terminal result. Missing coverage is not a pass.", row.job_id);
      database.db.prepare("INSERT INTO scan_events (id, seq, scan_id, event_type, safe_message, safe_metadata_json, created_at) SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ? FROM scan_events WHERE scan_id = ?").run(randomUUID(), row.job_id, cleanupRequired ? "MUTATION_CLEANUP_REQUIRED" : "SCAN_INTERRUPTED", "Expired worker evidence is retained; execution was not replayed.", JSON.stringify({ cleanupRequired, workerId: row.worker_id, leaseKind: row.kind }), nowIso(), row.job_id);
      database.db.prepare(`UPDATE ${table(row)} SET released_at = ?, release_category = 'EXPIRED' WHERE job_id = ? AND worker_id = ? AND released_at IS NULL`).run(nowIso(), row.job_id, row.worker_id);
      database.db.prepare("UPDATE worker_resources SET state = 'UNKNOWN_RETAINED', evidence_json = ?, updated_at = ? WHERE worker_id = ? AND state IN ('CREATED','RUNNING','DRAINING')").run(JSON.stringify({ reason: "ORPHAN_EXIT_OR_IDENTITY_CHANGE", filesAdopted: false, deletionAuthorized: false }), nowIso(), row.worker_id);
      new WorkerGovernanceRepository(database).setFleetQuarantine(true, "Expired worker custody is unresolved; retained evidence requires operator review.");
    });
    recovered.add(row.job_id);
  }
  return [...recovered];
}
