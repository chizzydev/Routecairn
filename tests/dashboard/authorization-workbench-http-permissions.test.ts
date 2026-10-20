import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("preserves actual HTTP 401/403 permission outcomes across server and organization boundaries", async () => {
  const root = createOwnedTestDirectory("authorization-http-permissions"),
    paths = resolveDashboardPaths(root),
    db = new DashboardDatabase(paths.databasePath);
  db.migrate();
  const origin = "https://authorization.fixture.test",
    sessionSecret = "owned-authorization-http-session-secret",
    sessions = new ServerSessionManager(db, {
      publicOrigin: origin,
      sessionSecret,
      trustProxy: true,
      developmentInsecureHttp: false
    });
  await sessions.createFirstOwner("owner@fixture.test", "Owned fixture password 39!");
  await sessions.createUser({ login: "viewer@fixture.test", password: "Owned fixture password 39!", role: "VIEWER" });
  const low = await sessions.createUser({
    login: "low@fixture.test",
    password: "Owned fixture password 39!",
    role: "OWNER"
  });
  db.db.prepare("UPDATE organization_memberships SET role='VIEWER' WHERE user_id=?").run(low);
  db.close();
  const handle = await startDashboardServer({
    dataDir: root,
    mode: "server",
    port: 0,
    publicOrigin: origin,
    sessionSecret,
    trustProxy: true
  });
  const receipts: Record<string, unknown>[] = [];
  try {
    expect((await fetch(handle.url + "/api/authorization-workbench")).status).toBe(401);
    for (const login of ["viewer@fixture.test", "low@fixture.test"]) {
      const auth = await fetch(handle.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login, password: "Owned fixture password 39!" })
      });
      expect(auth.status).toBe(200);
      const body = (await auth.json()) as { csrfToken: string },
        cookie = auth.headers.get("set-cookie")!.split(";")[0]!;
      const response = await fetch(handle.url + "/api/authorization-workbench/preview", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin,
          "x-forwarded-proto": "https",
          cookie,
          "x-csrf-token": body.csrfToken
        },
        body: "{}"
      });
      const result = await response.json();
      receipts.push({ actor: login, status: response.status, result });
      expect(response.status).toBe(403);
    }
    writeFileSync(
      join(root, "HTTP_PERMISSION_RECEIPT.json"),
      JSON.stringify(
        { receipts, actualLoopbackHTTP: true, proxyHeadersSynthetic: true, noScanAuthorized: true },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await handle.close();
    retainOwnedTestDirectory(root);
  }
});
