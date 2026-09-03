import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))));
});

describe("dashboard immutable reviewed plan execution", () => {
  it("executes the verified snapshot and rejects a manifest changed while its job is queued", async () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-immutable-worker-"));
    let releaseFirst!: () => void;
    const firstRelease = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstRequestSeen!: () => void;
    const firstSeen = new Promise<void>((resolve) => { firstRequestSeen = resolve; });
    let hold = true;
    const target = await fixture(async (_request, response) => {
      if (hold) {
        hold = false;
        firstRequestSeen();
        await firstRelease;
      }
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<!doctype html><title>immutable plan fixture</title>");
    });
    const paths = resolveDashboardPaths(directory);
    const database = new DashboardDatabase(paths.databasePath);
    database.migrate();
    const execution = new ScanExecutionService(database, paths);
    try {
      const firstScope = join(directory, "first-scope.json");
      const queuedScope = join(directory, "queued-scope.json");
      const scope = { ...exampleScope, program: "immutable-reviewed-plan", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 20, concurrency: 1 };
      writeFileSync(firstScope, JSON.stringify(scope));
      writeFileSync(queuedScope, JSON.stringify(scope));
      const request = (scopeFile: string) => ({ target, scopeFile, profile: "quick" as const, includeModules: ["baseline"], maxRequests: 20, rateLimitPerSecond: 20, concurrency: 1 });

      const firstId = await execution.enqueue(request(firstScope));
      await waitForRequestOrFailure(firstSeen, database, firstId);
      const changedId = await execution.enqueue(request(queuedScope));
      writeFileSync(queuedScope, JSON.stringify({ ...scope, program: "changed-after-review", allowedDomains: ["invalid.example"] }));
      releaseFirst();

      await expect.poll(() => scanStatus(database, firstId), { timeout: 20_000 }).toBe("COMPLETED");
      await expect.poll(() => scanStatus(database, changedId), { timeout: 20_000 }).toBe("FAILED");
      const changed = database.db.prepare("SELECT error_summary FROM scans WHERE id = ?").get(changedId) as { error_summary: string };
      expect(changed.error_summary).toContain("EXECUTABLE_PLAN_SOURCE_CHANGED:scopeFile");

      const verified = database.db.prepare("SELECT plan_binding, worker_verified_at, worker_verified_binding, ciphertext FROM scan_executable_plans WHERE scan_id = ?").get(firstId) as Record<string, string>;
      expect(verified.worker_verified_at).toBeTruthy();
      expect(verified.worker_verified_binding).toBe(verified.plan_binding);
      expect(verified.ciphertext).not.toContain("immutable-reviewed-plan");
      const detail = new ScanRepository(database).detail(firstId) as { executablePlan: Record<string, unknown> };
      expect(detail.executablePlan).toMatchObject({ plan_binding: verified.plan_binding, worker_verified_binding: verified.plan_binding });
      expect(detail.executablePlan).not.toHaveProperty("ciphertext");
      expect(detail.executablePlan).not.toHaveProperty("nonce");
      expect(detail.executablePlan).not.toHaveProperty("auth_tag");
      const events = database.db.prepare("SELECT event_type FROM scan_events WHERE scan_id = ? ORDER BY seq").all(firstId) as Array<{ event_type: string }>;
      expect(events.map((event) => event.event_type)).toEqual(expect.arrayContaining(["PLAN_BOUND", "PLAN_VERIFIED", "SCAN_COMPLETED"]));
    } finally {
      releaseFirst?.();
      await execution.shutdown();
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);

  it("rejects encrypted snapshot tampering before launching the queued worker", async () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-immutable-store-tamper-"));
    let releaseFirst!: () => void;
    const release = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let seen!: () => void;
    const firstSeen = new Promise<void>((resolve) => { seen = resolve; });
    let hold = true;
    const target = await fixture(async (_request, response) => {
      if (hold) { hold = false; seen(); await release; }
      response.writeHead(200, { "content-type": "text/plain" }); response.end("ok");
    });
    const paths = resolveDashboardPaths(directory);
    const database = new DashboardDatabase(paths.databasePath);
    database.migrate();
    const execution = new ScanExecutionService(database, paths);
    try {
      const scopeFile = join(directory, "scope.json");
      writeFileSync(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], rateLimitPerSecond: 20, concurrency: 1 }));
      const request = { target, scopeFile, profile: "quick" as const, includeModules: ["baseline"], maxRequests: 20, rateLimitPerSecond: 20, concurrency: 1 };
      const firstId = await execution.enqueue(request);
      await waitForRequestOrFailure(firstSeen, database, firstId);
      const tamperedId = await execution.enqueue(request);
      const row = database.db.prepare("SELECT ciphertext FROM scan_executable_plans WHERE scan_id = ?").get(tamperedId) as { ciphertext: string };
      database.db.prepare("UPDATE scan_executable_plans SET ciphertext = ? WHERE scan_id = ?").run(`${row.ciphertext.startsWith("A") ? "B" : "A"}${row.ciphertext.slice(1)}`, tamperedId);
      releaseFirst();
      await expect.poll(() => scanStatus(database, firstId), { timeout: 20_000 }).toBe("COMPLETED");
      await expect.poll(() => scanStatus(database, tamperedId), { timeout: 20_000 }).toBe("FAILED");
      const failed = database.db.prepare("SELECT error_summary FROM scans WHERE id = ?").get(tamperedId) as { error_summary: string };
      expect(failed.error_summary).toContain("EXECUTABLE_PLAN_SNAPSHOT_AUTHENTICATION_FAILED");
      expect(database.db.prepare("SELECT COUNT(*) AS total FROM scan_workers WHERE current_job_id = ?").get(tamperedId)).toMatchObject({ total: 0 });
    } finally {
      releaseFirst?.();
      await execution.shutdown();
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }, 35_000);
});

async function fixture(handler: Parameters<typeof createServer>[0]): Promise<string> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function scanStatus(database: DashboardDatabase, scanId: string): string {
  return (database.db.prepare("SELECT status FROM scans WHERE id = ?").get(scanId) as { status: string }).status;
}

async function waitForRequestOrFailure(requestSeen: Promise<void>, database: DashboardDatabase, scanId: string): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const settled = await Promise.race([requestSeen.then(() => true), new Promise<false>((resolve) => setTimeout(() => resolve(false), 50))]);
    if (settled) return;
    const row = database.db.prepare("SELECT status, error_summary FROM scans WHERE id = ?").get(scanId) as { status: string; error_summary?: string };
    if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(row.status)) throw new Error(`Fixture request was not reached: ${row.status} ${row.error_summary ?? ""}`);
  }
  throw new Error("Fixture request was not reached before timeout.");
}
