import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { cancellationFixture } from "../helpers/cancellation-fixture.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

async function authenticate(url: string, bootstrapUrl: string) {
  const response = await fetch(`${url}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: new URL(bootstrapUrl).hash.replace("#bootstrap=", "") }) });
  expect(response.status).toBe(200);
  const cookie = response.headers.get("set-cookie")!.split(";")[0]!;
  const { csrfToken } = await response.json() as { csrfToken: string };
  return { cookie, origin: url, "x-csrf-token": csrfToken, "content-type": "application/json" };
}

describe("dashboard cancellation and partial evidence", () => {
  for (const mode of ["slow-restoration", "failed-restoration", "forced-termination", "shutdown"] as const) {
    it(`preserves evidence and cleanup state for ${mode}`, async () => {
      const directory = process.env.ROUTECAIRN_MUTATION_DIR!;
      const fixture = await cancellationFixture(join(directory, "fixture"), { cleanupDelayMs: mode === "slow-restoration" || mode === "shutdown" ? 6000 : 10, cleanupFails: mode === "failed-restoration", holdCleanup: mode === "forced-termination" });
      const dataDir = join(directory, "dashboard");
      const handle = await startDashboardServer({ dataDir, port: 0 });
      let closed = false;
      try {
        const headers = await authenticate(handle.url, handle.bootstrapUrl!);
        const created = await fetch(`${handle.url}/api/scans`, { method: "POST", headers, body: JSON.stringify(fixture.scanRequest) });
        const body = await created.json() as { scanId: string; error?: unknown };
        expect(created.status, JSON.stringify(body)).toBe(202);
        const scanId = body.scanId;
        await expect.poll(() => fixture.received.includes("/hold"), { timeout: 15000 }).toBe(true);
        const started = Date.now();
        if (mode === "shutdown") {
          await handle.close(); closed = true;
          expect(Date.now() - started).toBeGreaterThan(5000);
          expect(fixture.restored).toBe(true);
          const database = new DashboardDatabase(resolveDashboardPaths(dataDir).databasePath);
          try {
            expect(database.db.prepare("SELECT status FROM scans WHERE id = ?").get(scanId)).toMatchObject({ status: "CANCELLED" });
            expect(database.db.prepare("SELECT COUNT(*) AS total FROM artifacts WHERE scan_id = ?").get(scanId)).toMatchObject({ total: 3 });
          } finally { database.close(); }
          return;
        }
        const cancelled = await fetch(`${handle.url}/api/scans/${scanId}/cancel`, { method: "POST", headers, body: "{}" });
        expect(cancelled.ok).toBe(true);
        await expect.poll(() => fixture.received.includes("/fixture/cleanup"), { timeout: 10000 }).toBe(true);
        if (mode === "forced-termination") {
          const database = new DashboardDatabase(resolveDashboardPaths(dataDir).databasePath);
          try {
            const worker = database.db.prepare("SELECT process_id FROM scan_workers WHERE current_job_id = ?").get(scanId) as { process_id: number };
            process.kill(worker.process_id, "SIGKILL");
          } finally { database.close(); }
        }
        const detail = async () => (await (await fetch(`${handle.url}/api/scans/${scanId}/detail`, { headers })).json()) as any;
        await expect.poll(async () => (await detail()).scan.status, { timeout: 20000 }).toBe(mode === "forced-termination" ? "INTERRUPTED" : "CANCELLED");
        const final = await detail();
        expect(final.artifacts).toHaveLength(3);
        expect(final.findings.length).toBeGreaterThan(0);
        const json = final.artifacts.find((artifact: any) => artifact.artifact_type === "JSON_REPORT");
        const download = await fetch(`${handle.url}/api/artifacts/${json.id}/download`, { headers });
        const raw = await download.text();
        const report = JSON.parse(raw);
        expect(raw).not.toContain("cancel-cleanup-secret");
        expect(report.execution.partial).toBe(true);
        expect(report.authenticationLifecycle.observations[0].caseId).toBe("retained-evidence");
        if (mode === "slow-restoration") {
          expect(Date.now() - started).toBeGreaterThan(5000);
          expect(fixture.restored).toBe(true);
          expect(report.authenticationLifecycle.observations[1].cleanupOutcome).toBe("ROLLBACK_VERIFIED");
          expect(report.execution.cleanup.state).toBe("CLEAR");
        } else {
          expect(report.execution.cleanup.state).toBe("REQUIRED");
          const checkpoint = await readFile(join(directory, "auth-lifecycle-cancelled-case.recovery.enc"), "utf8");
          expect(checkpoint).not.toContain("cancel-cleanup-secret");
          expect(final.events.some((event: any) => event.eventType === "MUTATION_CLEANUP_REQUIRED")).toBe(true);
        }
        if (mode === "forced-termination") {
          const originalFindingCount = final.findings.length;
          await handle.close(); closed = true;
          const database = new DashboardDatabase(resolveDashboardPaths(dataDir).databasePath);
          try {
            database.db.prepare("UPDATE scans SET json_report_artifact_id = NULL, markdown_report_artifact_id = NULL, html_report_artifact_id = NULL WHERE id = ?").run(scanId);
            database.db.prepare("DELETE FROM artifacts WHERE scan_id = ?").run(scanId);
          } finally { database.close(); }
          const restarted = await startDashboardServer({ dataDir, port: 0 });
          try {
            const restartedHeaders = await authenticate(restarted.url, restarted.bootstrapUrl!);
            const restartedDetail = async () => (await (await fetch(`${restarted.url}/api/scans/${scanId}/detail`, { headers: restartedHeaders })).json()) as any;
            await expect.poll(async () => (await restartedDetail()).artifacts.length, { timeout: 10000 }).toBe(3);
            expect((await restartedDetail()).findings).toHaveLength(originalFindingCount);
          } finally { await restarted.close(); }
        }
      } finally { if (!closed) await handle.close(); await fixture.close(); }
    }, 45000);
  }
});
