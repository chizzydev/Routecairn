import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

describe("dashboard worker operations API", () => {
  it("exposes diagnostics and audited fleet quarantine controls", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "routecairn-worker-api-"));
    const handle = await startDashboardServer({ dataDir: directory, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
    try {
      const auth = await authenticate(handle.url, handle.bootstrapUrl!);
      const initial = await get<any>(handle.url, "/api/workers/diagnostics", auth.cookie);
      expect(initial).toMatchObject({ dispatchState: "NORMAL", crashCount: 0, workers: [] });
      expect(initial.policy).toMatchObject({ memoryBytes: 768 * 1024 * 1024, cleanupGraceMs: 135000 });

      await post(handle.url, "/api/workers/fleet/quarantine", auth, { reason: "Planned isolation test window" });
      expect(await get<any>(handle.url, "/api/workers/diagnostics", auth.cookie)).toMatchObject({ dispatchState: "QUARANTINED", quarantineReason: "Planned isolation test window" });
      await post(handle.url, "/api/workers/fleet/release", auth, {});
      expect(await get<any>(handle.url, "/api/workers/diagnostics", auth.cookie)).toMatchObject({ dispatchState: "NORMAL", crashCount: 0 });
      const audit = await get<any>(handle.url, "/api/audit-events", auth.cookie);
      expect(audit.events.map((event: { action: string }) => event.action)).toEqual(expect.arrayContaining(["WORKER_FLEET_QUARANTINED", "WORKER_FLEET_RELEASED"]));
    } finally {
      await handle.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

async function authenticate(baseUrl: string, bootstrapUrl: string): Promise<{ cookie: string; csrf: string }> {
  const token = new URL(bootstrapUrl).hash.replace("#bootstrap=", "");
  const response = await fetch(`${baseUrl}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
  return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: (await response.json() as { csrfToken: string }).csrfToken };
}

async function get<T>(baseUrl: string, path: string, cookie: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } });
  if (!response.ok) throw new Error(`${path}: ${response.status} ${await response.text()}`);
  return await response.json() as T;
}

async function post(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<void> {
  const response = await fetch(`${baseUrl}${path}`, { method: "POST", headers: { cookie: auth.cookie, "x-csrf-token": auth.csrf, "content-type": "application/json", origin: baseUrl }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`${path}: ${response.status} ${await response.text()}`);
}
