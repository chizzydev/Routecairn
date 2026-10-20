import { it, expect } from "vitest";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("protects immutable schema and comparison HTTP reads, imports and creation without wire side effects", async () => {
  const f = await schemaApplicationFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const { schema, mappingInput } = f.makeInput(),
      a = await f.mapping.create(f.org, mappingInput, "operator"),
      b = await f.mapping.create(f.org, mappingInput, "operator"),
      comparison = f.comparisons.create(
        f.org,
        { baselineRevisionId: a.revisionId, currentRevisionId: b.revisionId },
        "operator"
      );
    await f.execution.shutdown();
    const publicOrigin = "https://schema-permissions.fixture.test",
      sessionSecret = "owned-schema-http-session-secret",
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
      { name: "Other schema org", slug: "other-schema" },
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
    const base = "/api/authorization-workbench/mapping";
    for (const actor of ["viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@fixture.test", password: "Disposable password 49!" })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
        session = (await login.json()) as { csrfToken: string };
      for (const path of [base + "/schemas/" + schema.revisionId, base + "/comparisons/" + comparison.comparisonId]) {
        const r = await fetch(server.url + path, { headers: { cookie, "x-forwarded-proto": "https" } });
        const body = await r.json();
        receipts.push({ actor, path, status: r.status, body });
        expect(r.status).toBe(actor === "viewer" ? 403 : 200);
        expect(JSON.stringify(body)).not.toContain("Bearer numeric-");
        if (actor === "analyst") {
          const wrong = await fetch(server.url + path, {
            headers: { cookie, "x-forwarded-proto": "https", "x-routecairn-organization-id": foreign }
          });
          expect(wrong.status).toBe(404);
          receipts.push({ actor, path, foreignStatus: wrong.status });
        }
      }
      const r = await fetch(server.url + base + "/schemas", {
        method: "POST",
        headers: {
          cookie,
          "content-type": "application/json",
          origin: publicOrigin,
          "x-forwarded-proto": "https",
          "x-csrf-token": session.csrfToken
        },
        body: JSON.stringify({ targetId: f.targetId, document: f.document })
      });
      expect(r.status).toBe(actor === "viewer" ? 403 : 201);
      receipts.push({ actor, importStatus: r.status });
      if (actor === "analyst") {
        const csrf = await fetch(server.url + base + "/comparisons", {
          method: "POST",
          headers: { cookie, "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
          body: JSON.stringify({ baselineRevisionId: a.revisionId, currentRevisionId: b.revisionId })
        });
        expect(csrf.status).toBe(401);
        receipts.push({ actor, missingCsrf: csrf.status });
      }
    }
    expect(f.wire).toHaveLength(0);
    writeFileSync(
      join(f.root, "SCHEMA_HTTP_RECEIPT.json"),
      JSON.stringify({ receipts, noApplicationRequests: true, actualHTTP: true, actualSQLite: true }, null, 2),
      { flag: "wx" }
    );
  } finally {
    await server?.close();
    await f.close();
  }
});
