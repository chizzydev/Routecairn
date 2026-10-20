import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { ChildProcess } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import type { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { exampleScope } from "../../src/config/defaults.js";

export async function workerFixture(hold = false) {
  const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT; if (!parent || process.platform !== "win32") throw Error("Explicit Windows lab required");
  const resource = OwnedTemporaryResource.create(parent, { purpose: "native-scan-worker-fixture" });
  let release!: () => void; const released = new Promise<void>(r => { release = r; });
  let requests = 0;
  const server = createServer(async (request, response) => {
    requests++;
    if (hold) await released;
    response.writeHead(request.url === "/" ? 200 : 404, { "content-type": "text/plain", connection: "close" }); response.end("DISPOSABLE_WORKER_FIXTURE");
  });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const paths = resolveDashboardPaths(resource.root), database = new DashboardDatabase(paths.databasePath); database.migrate();
  const scopeFile = join(resource.root, "scope.json");
  const scope = { ...exampleScope, program: "owned-windows-worker", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 20, concurrency: 1 };
  writeFileSync(scopeFile, JSON.stringify(scope), { flag: "wx" });
  const execution = new ScanExecutionService(database, paths);
  const workers = (execution as unknown as { workers: ScanWorkerManager }).workers;
  const request = { target, scopeFile, profile: "quick" as const, includeModules: ["baseline"], maxRequests: 4, rateLimitPerSecond: 20, concurrency: 1 };
  const status = (id: string) => (database.db.prepare("SELECT status FROM scans WHERE id = ?").get(id) as { status: string }).status;
  const child = (id: string) => (workers as unknown as { active: Map<string, { child: ChildProcess }> }).active.get(id)?.child;
  const capture = (name: string) => {
    const receipt = { version: 1, kind: "REAL_NATIVE_WINDOWS_WORKER_LOOPBACK_ONLY", root: resource.root, target, requests, sqlite: { journal: database.db.pragma("journal_mode"), integrity: database.db.pragma("integrity_check"), foreignKeys: database.db.pragma("foreign_key_check"), migrations: database.db.prepare("SELECT version FROM dashboard_migrations").all(), scans: database.db.prepare("SELECT id, status, error_summary FROM scans").all(), leases: database.db.prepare("SELECT * FROM scan_job_leases").all(), recoveryLeases: database.db.prepare("SELECT * FROM controlled_mutation_recovery_leases").all(), workers: database.db.prepare("SELECT id, process_id, state, failure_category FROM scan_workers").all(), resources: database.db.prepare("SELECT * FROM worker_resources").all(), events: database.db.prepare("SELECT scan_id, event_type, safe_message FROM scan_events ORDER BY seq").all(), plans: database.db.prepare("SELECT scan_id, plan_binding, worker_verified_binding, worker_verified_at FROM scan_executable_plans").all(), artifacts: database.db.prepare("SELECT scan_id, artifact_type, canonical_path FROM artifacts").all() } };
    writeFileSync(join(resource.root, name + ".json"), JSON.stringify(receipt, null, 2), { flag: "wx" }); return receipt;
  };
  return { resource, database, execution, workers, request, scope, scopeFile, paths, child, status, release, requests: () => requests,
    seen: async () => { await expect.poll(() => requests, { timeout: 15000 }).toBeGreaterThan(0); }, capture,
    close: async () => { release(); try { await execution.shutdown(); capture("NATIVE_SQLITE_RECEIPT"); } finally { database.close(); server.closeAllConnections(); await new Promise<void>((r, reject) => server.close(e => e ? reject(e) : r())); resource.retain("FIXTURE_FINISHED"); } }
  };
}
