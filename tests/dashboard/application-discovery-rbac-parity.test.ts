import { it, expect } from "vitest";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("preserves canonical summary reads for organization viewers while refusing resource-use mutations over authenticated HTTP", async () => {
  const f = await discoveryApplicationFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const a = await f.acquire(f.seedInput),
      p = f.propose(a.revision.revisionId);
    await f.execution.shutdown();
    const publicOrigin = "https://discovery.fixture.test",
      sessionSecret = "owned-discovery-http-session-secret",
      sessions = new ServerSessionManager(f.database, {
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
      }),
      foreign = new OrganizationService(f.database).create(
        { name: "Other discovery org", slug: "other-discovery" },
        analyst
      );
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin,
      sessionSecret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const base = "/api/authorization-workbench/mapping/discovery",
      wire = f.wire.length;
    for (const actor of ["viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@fixture.test", password: "Disposable password 49!" })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
        session = (await login.json()) as { csrfToken: string };
      const headers = {
        cookie,
        "content-type": "application/json",
        origin: publicOrigin,
        "x-forwarded-proto": "https",
        "x-csrf-token": session.csrfToken
      };
      if (actor === "analyst")
        f.database.db
          .prepare("UPDATE organization_memberships SET role='VIEWER' WHERE organization_id=? AND user_id=?")
          .run(f.org, analyst);
      const read = await fetch(server.url + base + "/" + p.proposalId, { headers }),
        body = await read.json();
      receipts.push({ actor, actual: read.status, expected: actor === "viewer" ? 403 : 200, body });
      f.capture("RBAC_" + actor, { receipts });
      expect(read.status).toBe(actor === "viewer" ? 403 : 200);
      expect(JSON.stringify(body)).not.toContain("Bearer archive-");
      const created = await fetch(server.url + base, { method: "POST", headers, body: JSON.stringify(p.input) });
      expect(created.status).toBe(403);
      receipts.push({ actor, read: read.status, create: created.status, body });
      if (actor === "analyst") {
        f.database.db
          .prepare("UPDATE organization_memberships SET role='ANALYST' WHERE organization_id=? AND user_id=?")
          .run(f.org, analyst);
        const restored = await fetch(server.url + base + "/" + p.proposalId, { headers });
        receipts.push({ restored: restored.status });
        expect(restored.status).toBe(200);
        const wrong = await fetch(server.url + base + "/" + p.proposalId, {
          headers: { ...headers, "x-routecairn-organization-id": foreign }
        });
        expect(wrong.status).toBe(404);
        const noCsrf = { ...headers };
        delete (noCsrf as Partial<typeof headers>)["x-csrf-token"];
        const csrf = await fetch(server.url + base, { method: "POST", headers: noCsrf, body: JSON.stringify(p.input) });
        expect(csrf.status).toBe(401);
        receipts.push({ foreign: wrong.status, missingCsrf: csrf.status });
      }
    }
    expect(f.wire).toHaveLength(wire);
    f.capture("DISCOVERY_AUTHENTICATED_HTTP", { receipts, noDiscoveryTransmission: true });
  } finally {
    await server?.close();
    await f.close();
  }
});
