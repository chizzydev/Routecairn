import { randomUUID } from "node:crypto";
import { describe, it, expect } from "vitest";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { workerFixture } from "../helpers/worker-lifecycle-fixture.js";

async function seededLease(kind: "scan" | "recovery", birth: "matching" | "wrong" | "invalid", recent = false) {
  const f = await workerFixture(); await f.execution.shutdown();
  const job = randomUUID(), worker = randomUUID(), now = new Date().toISOString(), expiry = new Date(Date.now() - (recent ? 1000 : 200000)).toISOString();
  new ScanRepository(f.database).create({ id: job, source: "DASHBOARD", status: "RUNNING", targetOrigin: f.request.target, safeTargetLabel: "SEEDED_LEASE_NOT_EXECUTED", profile: "quick", evidenceLevel: "minimal", safeConfigurationSummary: { seededLease: true, targetExecution: false } });
  f.database.db.prepare("INSERT INTO scan_workers (id, process_id, state, started_at, last_heartbeat_at, version) VALUES (?, ?, 'RUNNING', ?, ?, '2')").run(worker, process.pid, now, now);
  const realBirth = await windowsProcessBirth(process.pid, f.resource.directory("identity"));
  const processIdentity = birth === "invalid" ? "INVALID_JSON" : JSON.stringify({ pid: process.pid, birth: birth === "matching" ? realBirth : "111111111111111111" });
  f.database.db.prepare("INSERT INTO worker_resources (resource_id, worker_id, job_id, generation, resource_receipt_json, process_identity_json, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', ?, ?)").run(randomUUID(), worker, job, randomUUID(), JSON.stringify({ syntheticLeaseEvidenceOnly: true, deletionAuthorized: false }), processIdentity, now, now);
  const table = kind === "scan" ? "scan_job_leases" : "controlled_mutation_recovery_leases";
  if (kind === "scan") f.database.db.prepare(`INSERT INTO ${table} (job_id, worker_id, acquired_at, expires_at, last_renewed_at, attempt_number) VALUES (?, ?, ?, ?, ?, 1)`).run(job, worker, now, expiry, now);
  else f.database.db.prepare(`INSERT INTO ${table} (job_id, worker_id, acquired_at, expires_at, last_renewed_at) VALUES (?, ?, ?, ?, ?)`).run(job, worker, now, expiry, now);
  return { ...f, job, table };
}
describe.skipIf(process.platform !== "win32")("native SQLite orphan reconciliation controls (seeded leases; no scan)", () => {
  it("holds a matching live birth beyond the restoration grace and exposes that hold once", async () => {
    const f = await seededLease("scan", "matching");
    try {
      expect(await f.workers.recoverExpiredLeases()).toEqual([]); expect(await f.workers.recoverExpiredLeases()).toEqual([]);
      expect(f.status(f.job)).toBe("RUNNING");
      expect(f.database.db.prepare("SELECT COUNT(*) AS n FROM scan_events WHERE event_type = 'WORKER_RECOVERY_HELD'").get()).toEqual({ n: 1 });
      expect(f.requests()).toBe(0);
    } finally { await f.close(); }
  });
  it("does not adopt or signal a recycled PID, and retains UNKNOWN orphan evidence", async () => {
    const f = await seededLease("scan", "wrong");
    try {
      expect(await f.workers.recoverExpiredLeases()).toEqual([f.job]); expect(f.status(f.job)).toBe("INTERRUPTED");
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(f.job)).toEqual({ state: "UNKNOWN_RETAINED" });
      expect(f.database.db.prepare(`SELECT release_category FROM ${f.table} WHERE job_id = ?`).get(f.job)).toEqual({ release_category: "EXPIRED" }); expect(f.requests()).toBe(0);
    } finally { await f.close(); }
  });
  it("holds malformed identities without throwing or declaring a quiet pass", async () => {
    const f = await seededLease("scan", "invalid");
    try { expect(await f.workers.recoverExpiredLeases()).toEqual([]); expect(f.status(f.job)).toBe("RUNNING"); expect(f.database.db.prepare("SELECT safe_metadata_json FROM scan_events WHERE event_type = 'WORKER_RECOVERY_HELD'").get()).toMatchObject({ safe_metadata_json: expect.stringContaining("PROCESS_IDENTITY_UNKNOWN") }); }
    finally { await f.close(); }
  });
  it("preserves the full original restoration grace even after identity uncertainty", async () => {
    const f = await seededLease("scan", "wrong", true);
    try { expect(await f.workers.recoverExpiredLeases()).toEqual([]); expect(f.status(f.job)).toBe("RUNNING"); expect(f.database.db.prepare("SELECT safe_metadata_json FROM scan_events WHERE event_type = 'WORKER_RECOVERY_HELD'").get()).toMatchObject({ safe_metadata_json: expect.stringContaining("RESTORATION_GRACE") }); }
    finally { await f.close(); }
  });
  it("reconciles expired recovery leases as unresolved cleanup without replay", async () => {
    const f = await seededLease("recovery", "wrong");
    try { expect(await f.workers.recoverExpiredLeases()).toEqual([f.job]); expect(f.status(f.job)).toBe("INTERRUPTED"); expect(f.database.db.prepare("SELECT COUNT(*) AS n FROM scan_events WHERE event_type = 'MUTATION_CLEANUP_REQUIRED'").get()).toEqual({ n: 1 }); expect(f.requests()).toBe(0); }
    finally { await f.close(); }
  });
});
