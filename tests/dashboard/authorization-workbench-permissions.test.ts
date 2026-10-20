import { it, expect } from "vitest";
import type { ApiContext } from "../../src/dashboard/server/DashboardApiContext.js";
import { handleAuthorizationWorkbench } from "../../src/dashboard/server/DashboardAuthorizationWorkbenchApi.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
it.each(["VIEWER", "ORG_VIEWER", "FOREIGN_ORG"] as const)(
  "enforces real server and SQLite organization authority: %s",
  async (kind) => {
    const f = recoveryCenterFixture();
    try {
      const sessions = new ServerSessionManager(f.database, {
          publicOrigin: "http://127.0.0.1",
          sessionSecret: "fixture".repeat(8),
          trustProxy: false,
          developmentInsecureHttp: true
        }),
        role = kind === "VIEWER" ? "VIEWER" : "OWNER",
        id = await sessions.createUser({
          login: kind.toLowerCase() + "@fixture.test",
          password: "Owned-fixture-password-34!",
          role
        });
      if (kind === "ORG_VIEWER")
        f.database.db.prepare("UPDATE organization_memberships SET role='VIEWER' WHERE user_id=?").run(id);
      const context = {
        mode: "server",
        serverSessions: sessions,
        principal: { mode: "server", userId: id, login: kind, role, csrfToken: "fixture" },
        database: f.database,
        organizations: new OrganizationService(f.database),
        url: new URL("http://127.0.0.1/api/authorization-workbench/preview"),
        request: {
          method: "POST",
          headers: { "x-routecairn-organization-id": kind === "FOREIGN_ORG" ? f.other : f.scope.organizationId }
        },
        response: { setHeader() {} }
      } as unknown as ApiContext;
      await expect(handleAuthorizationWorkbench(context)).rejects.toThrow(
        kind === "VIEWER" ? "scans.create" : kind === "ORG_VIEWER" ? "resources.use" : "org.read"
      );
      expect(f.database.db.prepare("SELECT * FROM authorization_workbench_dispatches").all()).toEqual([]);
    } finally {
      f.close();
    }
  }
);
