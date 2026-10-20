import { it, expect } from "vitest";
import { heldOutApplicationFixture } from "../helpers/heldout-application-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("requires authenticated credential-creation and target authority for onboarding, with no implicit target I/O", async () => {
  const f = await heldOutApplicationFixture("helpdesk", false);
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  try {
    await f.execution.shutdown();
    const publicOrigin = "https://onboard.fixture.test",
      sessionSecret = "owned-onboarding-server-session-key",
      sessions = new ServerSessionManager(f.database, {
        publicOrigin,
        sessionSecret,
        trustProxy: true,
        developmentInsecureHttp: false
      });
    await sessions.createFirstOwner("owner@fixture.test", "Disposable password 49!");
    for (const role of ["ANALYST", "VIEWER"] as const)
      await sessions.createUser({
        login: role.toLowerCase() + "@fixture.test",
        password: "Disposable password 49!",
        role
      });
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
    const input = {
      displayName: "Owned onboarding HTTP Helpdesk",
      origin: f.origin,
      authorizationSummary: "Owner approves separately reviewed local GET observations only",
      identityPath: "/identity",
      principalField: "principal",
      tenantField: "tenant",
      roleField: "role",
      seedPath: f.prefix + "catalog/start",
      objectField: f.identityPath,
      objectTenantField: f.tenantPath,
      actors: Object.fromEntries(
        Object.entries(f.app.actors).map(([slot, a]) => [
          slot,
          { ...a, authorizationHeader: "Bearer heldout-helpdesk-" + slot, expiresAt: "2099-01-01T00:00:00Z" }
        ])
      ),
      ownedReadOnlyConfirmed: true
    };
    for (const role of ["viewer", "analyst", "owner"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: role + "@fixture.test", password: "Disposable password 49!" })
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
      const r = await fetch(server.url + "/api/authorization-workbench/mapping/onboarding", {
          method: "POST",
          headers,
          body: JSON.stringify(input)
        }),
        body = await r.json();
      receipts.push({ role, status: r.status, body });
      expect(r.status).toBe(role === "owner" ? 201 : 403);
      expect(JSON.stringify(body)).not.toContain("Bearer");
      if (role === "owner") {
        const missing = { ...headers };
        delete (missing as Partial<typeof headers>)["x-csrf-token"];
        const denied = await fetch(server.url + "/api/authorization-workbench/mapping/onboarding", {
          method: "POST",
          headers: missing,
          body: JSON.stringify(input)
        });
        expect(denied.status).toBe(401);
        receipts.push({ noCsrf: denied.status });
      }
    }
    expect(f.wire.length).toBe(0);
    expect(f.database.db.prepare("SELECT count(*) n FROM targets").get()).toEqual({ n: 1 });
    expect(f.database.db.prepare("SELECT count(*) n FROM scans").get()).toEqual({ n: 0 });
    f.capture("ONBOARDING_AUTHENTICATED_HTTP", { receipts, noTargetIO: true });
  } finally {
    await server?.close();
    await f.close();
  }
});
