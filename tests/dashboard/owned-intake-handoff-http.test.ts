import { it, expect } from "vitest";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
import { ownedIntakeExport } from "../helpers/owned-intake-export.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("enforces real authenticated intake/handoff org, resource, CSRF and role boundaries with zero implicit target traffic", async () => {
  const f = await deepBusinessFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      wire = f.wire.length;
    await f.execution.shutdown();
    const origin = "https://intake.fixture.test",
      secret = "owned-intake-session-secret-strong-2026",
      sessions = new ServerSessionManager(f.database, {
        publicOrigin: origin,
        sessionSecret: secret,
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
      foreign = new OrganizationService(f.database).create({ name: "Foreign intake", slug: "foreign-intake" }, analyst);
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin: origin,
      sessionSecret: secret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const base = server.url + "/api/authorization-workbench/mapping",
      body = {
        targetId: f.targetId,
        credentials: f.credentials,
        artifact: ownedIntakeExport(f),
        ownerScopeConfirmed: true,
        offlineOnlyConfirmed: true
      };
    expect((await fetch(base + "/hypotheses/" + p.proposalId + "/handoff")).status).toBe(401);
    for (const role of ["viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: role + "@fixture.test", password: "Disposable password 49!" })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
        session = (await login.json()) as { csrfToken: string },
        headers = {
          cookie,
          origin,
          "x-forwarded-proto": "https",
          "content-type": "application/json",
          "x-csrf-token": session.csrfToken
        };
      for (const suffix of ["/history", "/handoff"]) {
        const r = await fetch(base + "/hypotheses/" + p.proposalId + suffix, { headers });
        expect(r.status).toBe(role === "viewer" ? 403 : 200);
        const bytes = await r.text();
        expect(bytes).not.toMatch(/Bearer|authorizationHeader|synthetic-session/);
        receipts.push({ role, suffix, status: r.status, body: JSON.parse(bytes) });
      }
      const saved = await fetch(base + "/intake", { method: "POST", headers, body: JSON.stringify(body) });
      expect(saved.status).toBe(role === "viewer" ? 403 : 201);
      receipts.push({ role, intakeStatus: saved.status });
      if (role === "analyst") {
        expect(
          (
            await fetch(base + "/hypotheses/" + p.proposalId + "/handoff", {
              headers: { ...headers, "x-routecairn-organization-id": foreign }
            })
          ).status
        ).toBe(404);
        expect(
          (
            await fetch(base + "/intake", {
              method: "POST",
              headers: { cookie, origin, "x-forwarded-proto": "https", "content-type": "application/json" },
              body: JSON.stringify(body)
            })
          ).status
        ).toBe(401);
        expect(
          (
            await fetch(base + "/intake", {
              method: "POST",
              headers: { ...headers, "x-routecairn-organization-id": foreign },
              body: JSON.stringify(body)
            })
          ).status
        ).not.toBe(201);
      }
    }
    expect(f.wire.length).toBe(wire);
    expect(f.database.db.prepare("SELECT count(*) n FROM application_owned_intakes").get()).toEqual({ n: 1 });
    f.capture("OWNED_INTAKE_HANDOFF_AUTHENTICATED_HTTP", { receipts, wire });
  } finally {
    await server?.close();
    await f.close();
  }
});
