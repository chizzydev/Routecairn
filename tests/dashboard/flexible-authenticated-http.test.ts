import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { randomBytes } from "node:crypto";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("real authenticated HTTP protects registry review and uses the same native plan contract", async () => {
  const f = await flexibleDashboardFixture(1, true);
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  try {
    await f.execution.shutdown();
    const publicOrigin = "https://flexible.fixture.test",
      sessionSecret = randomBytes(32).toString("base64url"),
      password = randomBytes(24).toString("base64url"),
      sessions = new ServerSessionManager(f.database, {
        publicOrigin,
        sessionSecret,
        trustProxy: true,
        developmentInsecureHttp: false
      });
    await sessions.createFirstOwner("owner@fixture.test", password);
    await sessions.createUser({ login: "viewer@fixture.test", password, role: "VIEWER" });
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin,
      sessionSecret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const receipts: unknown[] = [];
    for (const role of ["viewer", "owner"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: role + "@fixture.test", password })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
        session = (await login.json()) as { csrfToken: string },
        headers = {
          cookie,
          "content-type": "application/json",
          origin: publicOrigin,
          "x-forwarded-proto": "https",
          "x-csrf-token": session.csrfToken
        };
      const response = await fetch(server.url + "/api/scans/actor-registry", {
          method: "POST",
          headers,
          body: JSON.stringify(f.input)
        }),
        body = (await response.json()) as { registry?: { actors: unknown[] }; requestsSent?: number };
      receipts.push({ role, status: response.status, body });
      expect(response.status).toBe(role === "owner" ? 200 : 403);
      expect(JSON.stringify(body)).not.toContain(f.tokens[0]);
      if (role === "owner") {
        expect(body.registry?.actors).toHaveLength(1);
        expect(body.requestsSent).toBe(0);
        const noCsrf = { ...headers };
        delete (noCsrf as Partial<typeof headers>)["x-csrf-token"];
        const denied = await fetch(server.url + "/api/scans/actor-registry", {
          method: "POST",
          headers: noCsrf,
          body: JSON.stringify(f.input)
        });
        expect(denied.status).toBe(401);
        receipts.push({ noCsrf: denied.status });
      }
    }
    expect(f.wire).toEqual([]);
    f.capture("FLEXIBLE_AUTHENTICATED_HTTP", receipts);
  } finally {
    await server?.close();
    await f.close();
  }
});
