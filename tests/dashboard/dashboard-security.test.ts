import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { redactDashboardValue } from "../../src/dashboard/security/Redaction.js";

describe("dashboard local API security", () => {
  it("refuses non-loopback binding", async () => {
    await expect(startDashboardServer({ host: "0.0.0.0" })).rejects.toThrow(/non-loopback/);
  });

  it("uses one-shot bootstrap and CSRF-protected mutations", async () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-dashboard-server-"));
    const ui = resolve(dir, "ui");
    writeFileSync(resolve(dir, "index.tmp"), "");
    try {
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: ui });
      try {
        const token = new URL(handle.bootstrapUrl).hash.replace("#bootstrap=", "");
        const first = await fetch(`${handle.url}/api/session/bootstrap`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        });
        expect(first.status).toBe(200);
        const cookie = first.headers.get("set-cookie")?.split(";")[0] ?? "";
        const csrf = (await first.json() as { csrfToken: string }).csrfToken;
        const second = await fetch(`${handle.url}/api/session/bootstrap`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        });
        expect(second.status).toBe(401);
        const rejected = await fetch(`${handle.url}/api/scans`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie, origin: handle.url },
          body: JSON.stringify({})
        });
        expect(rejected.status).toBe(401);
        expect(csrf.length).toBeGreaterThan(20);

        const refreshed = await fetch(`${handle.url}/api/auth/csrf`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie, origin: handle.url },
          body: "{}"
        });
        expect(refreshed.status).toBe(200);
        const nextCsrf = (await refreshed.json() as { csrfToken: string }).csrfToken;
        expect(nextCsrf).not.toBe(csrf);

        const firstTab = await fetch(`${handle.url}/api/projects`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie, origin: handle.url, "x-csrf-token": csrf },
          body: JSON.stringify({ name: "First tab CSRF", tags: [], defaultScope: {} })
        });
        expect(firstTab.status).toBe(201);

        const accepted = await fetch(`${handle.url}/api/projects`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie, origin: handle.url, "x-csrf-token": nextCsrf },
          body: JSON.stringify({ name: "Second tab CSRF", tags: [], defaultScope: {} })
        });
        expect(accepted.status).toBe(201);
      } finally {
        await handle.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("redacts auth material in dashboard structured data", () => {
    expect(redactDashboardValue({ headers: { authorization: "Bearer secret-token", cookie: "sid=secret" }, url: "https://x.test/?token=secret" })).toEqual({
      headers: { authorization: "<redacted>", cookie: "<redacted>" },
      url: "https://x.test/?token=<redacted>"
    });
  });

  it("bootstraps the first hosted owner once from deployment environment", async () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-dashboard-bootstrap-"));
    const priorLogin = process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN;
    const priorPassword = process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD;
    process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN = "bootstrap-owner@example.test";
    process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD = "Correct-Horse-Battery-Staple-2026!";
    let handle: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
    try {
      handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.test", sessionSecret: "s".repeat(48), trustProxy: true, uiDistDir: resolve(dir, "ui") });
      delete process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN;
      delete process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD;
      const response = await fetch(`${handle.url}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json", origin: "https://routecairn.example.test", "x-forwarded-proto": "https" }, body: JSON.stringify({ login: "bootstrap-owner@example.test", password: "Correct-Horse-Battery-Staple-2026!" }) });
      expect(response.status).toBe(200);
    } finally {
      if (handle) await handle.close();
      if (priorLogin === undefined) delete process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN; else process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN = priorLogin;
      if (priorPassword === undefined) delete process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD; else process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD = priorPassword;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
