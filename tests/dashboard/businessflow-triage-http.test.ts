import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("enforces genuine authenticated HTTP triage read, organization, resource, CSRF and immutable note boundaries", async () => {
  const f = await businessFlowFixture("orders");
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
    await f.execution.shutdown();
    const origin = "https://businessflow.fixture.test",
      secret = "owned-businessflow-session-secret",
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
      foreign = new OrganizationService(f.database).create({ name: "Other flow", slug: "other-flow-new" }, analyst);
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin: origin,
      sessionSecret: secret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const base = server.url + "/api/authorization-workbench/mapping/hypotheses/" + p.proposalId;
    expect((await fetch(base + "/triage")).status).toBe(401);
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
      const response = await fetch(base + "/triage", { headers }),
        body = (await response.json()) as { digest: string };
      receipts.push({ role, status: response.status, body });
      expect(response.status).toBe(role === "viewer" ? 403 : 200);
      expect(JSON.stringify(body)).not.toContain("Bearer");
      const note = {
        digest: body.digest ?? "a".repeat(64),
        disposition: "NEEDS_OWNER_CONTEXT",
        rationale: "This reviewed relationship requires exact owner context; no proof is inferred.",
        reviewConfirmed: true
      };
      const create = await fetch(base + "/triage-notes", { method: "POST", headers, body: JSON.stringify(note) });
      expect(create.status).toBe(role === "viewer" ? 403 : 201);
      receipts.push({ role, noteStatus: create.status });
      if (role === "analyst") {
        expect(
          (await fetch(base + "/triage", { headers: { ...headers, "x-routecairn-organization-id": foreign } })).status
        ).toBe(404);
        expect(
          (
            await fetch(base + "/triage-notes", {
              method: "POST",
              headers: { cookie, origin, "x-forwarded-proto": "https", "content-type": "application/json" },
              body: JSON.stringify(note)
            })
          ).status
        ).toBe(401);
        f.database.db
          .prepare("UPDATE organization_memberships SET role=? WHERE organization_id=? AND user_id=?")
          .run("VIEWER", f.org, analyst);
        expect((await fetch(base + "/triage", { headers })).status).toBe(200);
        expect(
          (await fetch(base + "/triage-notes", { method: "POST", headers, body: JSON.stringify(note) })).status
        ).toBe(403);
      }
    }
    expect(f.wire.length).toBe(12);
    expect(f.database.db.prepare("SELECT count(*) n FROM application_triage_notes").get()).toEqual({ n: 1 });
    f.capture("BUSINESSFLOW_HTTP_PERMISSIONS", { receipts, wireCount: f.wire.length, nativeSQLite: true });
    writeFileSync(
      join(f.root, "TRIAGE_NATIVE_SQLITE_ROWS.json"),
      JSON.stringify(f.database.db.prepare("SELECT * FROM application_triage_notes").all()),
      { flag: "wx" }
    );
  } finally {
    await server?.close();
    await f.close();
  }
});
