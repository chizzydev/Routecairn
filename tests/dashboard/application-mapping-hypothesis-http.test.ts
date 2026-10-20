import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("enforces real authenticated hypothesis metadata, organization, mutation and CSRF authority", async () => {
  const f = await applicationMappingFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const a = await f.acquire(),
      service = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = service.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
    await f.execution.shutdown();
    const publicOrigin = "https://hypothesis.fixture.test",
      sessionSecret = "owned-hypothesis-http-session-secret",
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
    });
    const foreign = new OrganizationService(f.database).create(
      { name: "Other hypotheses", slug: "other-hypotheses" },
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
    const base = "/api/authorization-workbench/mapping/hypotheses";
    expect((await fetch(server.url + base + "/" + p.proposalId)).status).toBe(401);
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
      for (const path of [base + "?mapRevisionId=" + a.revision.revisionId, base + "/" + p.proposalId]) {
        const r = await fetch(server.url + path, { headers });
        const body = await r.json();
        receipts.push({ actor, path, status: r.status, body });
        expect(r.status).toBe(actor === "viewer" ? 403 : 200);
        expect(JSON.stringify(body)).not.toContain("Bearer fixture-");
        if (actor === "analyst")
          expect(
            (await fetch(server.url + path, { headers: { ...headers, "x-routecairn-organization-id": foreign } }))
              .status
          ).toBe(404);
      }
      const create = await fetch(server.url + base, {
        method: "POST",
        headers,
        body: JSON.stringify({ mapRevisionId: a.revision.revisionId })
      });
      expect(create.status).toBe(actor === "viewer" ? 403 : 201);
      receipts.push({ actor, createStatus: create.status });
      if (actor === "analyst") {
        const r = await fetch(server.url + base, {
          method: "POST",
          headers: { cookie, "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
          body: JSON.stringify({ mapRevisionId: a.revision.revisionId })
        });
        expect(r.status).toBe(401);
        receipts.push({ missingCsrf: r.status });
      }
    }
    expect(f.wire).toHaveLength(20);
    writeFileSync(
      join(f.root, "HYPOTHESIS_AUTHENTICATED_HTTP.json"),
      JSON.stringify(
        { receipts, actualHTTP: true, actualSQLite: true, applicationRequests: 20, noProposalWire: true },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await server?.close();
    await f.close();
  }
});
