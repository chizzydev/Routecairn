import { it, expect, vi } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
import { ServerSessionManager, PermissionError } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("proves inherited scan-read and organization-read policy over authenticated hypothesis and linked evidence HTTP", async () => {
  const f = await applicationMappingFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const a = await f.acquire(),
      h = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = h.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      matrix = await f.mapping.createMatrix(f.org, a.revision.revisionId, f.policy, "operator");
    await f.execution.shutdown();
    const publicOrigin = "https://roleflow.fixture.test",
      sessionSecret = "owned-roleflow-policy-session-secret",
      sessions = new ServerSessionManager(f.database, {
        publicOrigin,
        sessionSecret,
        trustProxy: true,
        developmentInsecureHttp: false
      });
    await sessions.createFirstOwner("owner@fixture.test", "Disposable password 49!");
    const viewer = await sessions.createUser({
        login: "viewer@fixture.test",
        password: "Disposable password 49!",
        role: "VIEWER"
      }),
      analyst = await sessions.createUser({
        login: "analyst@fixture.test",
        password: "Disposable password 49!",
        role: "ANALYST"
      });
    // Dashboard ANALYST, organization VIEWER: may read organization evidence, cannot use resources.
    f.database.db
      .prepare("UPDATE organization_memberships SET role=? WHERE organization_id=? AND user_id=?")
      .run("VIEWER", f.org, analyst);
    const foreign = new OrganizationService(f.database).create({ name: "Other flow", slug: "other-flow" }, analyst);
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin,
      sessionSecret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const base = "/api/authorization-workbench/mapping/hypotheses",
      paths = [
        base + "?mapRevisionId=" + a.revision.revisionId,
        base + "/" + p.proposalId,
        "/api/authorization-workbench/mapping/" + a.revision.revisionId,
        "/api/authorization-workbench/" + matrix.revisionId,
        "/api/scans/" + a.run.scanId
      ];
    for (const actor of ["viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@fixture.test", password: "Disposable password 49!" })
      });
      expect(login.status).toBe(200);
      const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
        session = (await login.json()) as { csrfToken: string },
        headers = {
          cookie,
          origin: publicOrigin,
          "x-forwarded-proto": "https",
          "content-type": "application/json",
          "x-csrf-token": session.csrfToken
        };
      for (const path of paths) {
        const r = await fetch(server.url + path, { headers });
        receipts.push({ actor, path, status: r.status });
        expect(r.status).toBe(actor === "viewer" && !path.startsWith("/api/scans/") ? 403 : 200);
      }
      if (actor === "analyst") {
        expect(
          (
            await fetch(server.url + base, {
              method: "POST",
              headers,
              body: JSON.stringify({ mapRevisionId: a.revision.revisionId })
            })
          ).status
        ).toBe(403);
        for (const path of paths)
          expect(
            (await fetch(server.url + path, { headers: { ...headers, "x-routecairn-organization-id": foreign } }))
              .status
          ).toBe(404);
        // Attenuation fault only: fixed product roles cannot express summary-without-scan-read.
        const original = ServerSessionManager.prototype.requirePermission;
        const attenuated = vi.spyOn(ServerSessionManager.prototype, "requirePermission").mockImplementation(function (
          this: ServerSessionManager,
          principal,
          permission
        ) {
          if (principal.userId === analyst && permission === "scans.read")
            throw new PermissionError("Test-owned deny scans.read");
          return original.call(this, principal, permission);
        });
        try {
          for (const path of paths) {
            const r = await fetch(server.url + path, { headers });
            receipts.push({
              actor: "AUTHENTICATED_ATTENUATED_SCAN_READ",
              path,
              status: r.status,
              syntheticPolicyAttenuation: true
            });
            expect(r.status).toBe(403);
          }
        } finally {
          attenuated.mockRestore();
        }
        f.database.db
          .prepare("UPDATE organization_memberships SET role=? WHERE organization_id=? AND user_id=?")
          .run("ANALYST", f.org, analyst);
        f.database.db
          .prepare("UPDATE dashboard_sessions SET revoked_at=? WHERE user_id=?")
          .run(new Date().toISOString(), analyst);
        expect((await fetch(server.url + base + "/" + p.proposalId, { headers })).status).toBe(401);
      }
    }
    expect(viewer).toBeTruthy();
    expect(f.wire).toHaveLength(20);
    writeFileSync(
      join(f.root, "ROLEFLOW_READ_POLICY_HTTP.json"),
      JSON.stringify(
        {
          verdict: "NO_DEFECT_IN_EXISTING_INTENDED_READ_CONTRACT",
          policy:
            "scans.read inherited; credentials.readSummary plus org.read for restricted metadata. resources.use required for mutation, not ordinary org evidence reads. No per-target grant/deny model exists.",
          receipts,
          requests: 20,
          productionAuthorizationChanged: false
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    vi.restoreAllMocks();
    await server?.close();
    await f.close();
  }
});
