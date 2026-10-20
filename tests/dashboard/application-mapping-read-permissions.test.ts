import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("enforces credential-summary read authority for mapping and advanced detail over authenticated HTTP", async () => {
  const f = await applicationMappingFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: { actor: string; path: string; status: number; expected: number; body: unknown }[] = [];
  try {
    const acquired = await f.acquire();
    const advanced = await f.mapping.createMatrix(f.org, acquired.revision.revisionId, f.policy, "operator");
    await f.execution.shutdown();
    const publicOrigin = "https://read-authority.fixture.test",
      sessionSecret = "owned-read-authority-session-secret";
    const sessions = new ServerSessionManager(f.database, {
      publicOrigin,
      sessionSecret,
      trustProxy: true,
      developmentInsecureHttp: false
    });
    await sessions.createFirstOwner("owner@fixture.test", "Disposable password 49!");
    await sessions.createUser({ login: "viewer@fixture.test", password: "Disposable password 49!", role: "VIEWER" });
    const analyst = await sessions.createUser({
      login: "analyst@fixture.test",
      password: "Disposable password 49!",
      role: "ANALYST"
    });
    const organizations = new OrganizationService(f.database),
      foreign = organizations.create({ name: "Other owned org", slug: "other-read-org" }, analyst);
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin,
      sessionSecret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const details = [
      "/api/authorization-workbench/mapping/" + acquired.revision.revisionId,
      "/api/authorization-workbench/" + advanced.revisionId
    ];
    for (const actor of ["viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@fixture.test", password: "Disposable password 49!" })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
      for (const path of [
        "/api/authorization-workbench/mapping",
        "/api/authorization-workbench",
        ...details,
        "/api/scans"
      ]) {
        const response = await fetch(server.url + path, { headers: { cookie, "x-forwarded-proto": "https" } });
        receipts.push({
          actor,
          path,
          status: response.status,
          expected: path === "/api/scans" ? 200 : actor === "viewer" ? 403 : 200,
          body: await response.json()
        });
      }
      if (actor === "analyst")
        for (const path of [...details, ...details.map((p) => p.replace(/[a-f0-9-]{36}$/, randomUUID()))]) {
          const response = await fetch(server.url + path, {
            headers: { cookie, "x-forwarded-proto": "https", "x-routecairn-organization-id": foreign }
          });
          receipts.push({ actor, path, status: response.status, expected: 404, body: await response.json() });
        }
    }
    for (const path of details) {
      const response = await fetch(server.url + path);
      receipts.push({
        actor: "unauthenticated",
        path,
        status: response.status,
        expected: 401,
        body: await response.json()
      });
    }
    writeFileSync(
      join(f.root, "AUTHENTICATED_GET_RECEIPT.json"),
      JSON.stringify(
        {
          receipts,
          csrfIndependentGet: true,
          actualNativeSQLite: true,
          actualLoopbackHTTP: true,
          syntheticProxyHeaders: true,
          integrity: f.database.db.pragma("integrity_check")
        },
        null,
        2
      ),
      { flag: "wx" }
    );
    expect(receipts.filter((r) => r.status !== r.expected)).toEqual([]);
    for (const r of receipts) {
      expect(JSON.stringify(r.body)).not.toContain("Bearer fixture-");
      if (r.status === 403) expect(JSON.stringify(r.body)).not.toContain(f.mappingInput.credentials.primary);
    }
  } finally {
    await server?.close();
    await f.close();
  }
});
