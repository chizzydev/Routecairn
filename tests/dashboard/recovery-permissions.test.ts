import { describe, it, expect } from "vitest";
import type { ApiContext } from "../../src/dashboard/server/DashboardApiContext.js";
import { recoveryScope } from "../../src/dashboard/server/DashboardRecoveryApi.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
import type { DashboardRole } from "../../src/dashboard/auth/Permissions.js";
describe("real server role and SQLite organization recovery authority", () => {
  it.each(["OWNER", "ANALYST", "VIEWER"] as DashboardRole[])(
    "derives %s authority from both permission layers",
    async (role) => {
      const f = recoveryCenterFixture();
      try {
        const sessions = new ServerSessionManager(f.database, {
            publicOrigin: "http://127.0.0.1",
            sessionSecret: "fixture".repeat(8),
            trustProxy: false,
            developmentInsecureHttp: true
          }),
          id = await sessions.createUser({
            login: role.toLowerCase() + "@fixture.test",
            password: "Owned-fixture-password-34!",
            role
          }),
          organizations = new OrganizationService(f.database),
          context = {
            mode: "server",
            serverSessions: sessions,
            principal: { mode: "server", userId: id, login: role, role, csrfToken: "fixture" },
            url: new URL("http://127.0.0.1/api/recovery-center"),
            request: { headers: { "x-routecairn-organization-id": f.scope.organizationId } },
            organizations
          } as unknown as ApiContext;
        const scope = recoveryScope(context);
        expect(scope.canReview).toBe(role !== "VIEWER");
        expect(scope.canRecover).toBe(role === "OWNER");
        expect(scope.canManageWorkers).toBe(role === "OWNER");
        expect(scope.canRecompute).toBe(role !== "VIEWER");
        context.request.headers["x-routecairn-organization-id"] = f.other;
        expect(() => recoveryScope(context)).toThrow("org.read");
      } finally {
        f.close();
      }
    }
  );
  it("downgrades an installation owner whose organization membership is read-only", async () => {
    const f = recoveryCenterFixture();
    try {
      const sessions = new ServerSessionManager(f.database, {
          publicOrigin: "http://127.0.0.1",
          sessionSecret: "fixture".repeat(8),
          trustProxy: false,
          developmentInsecureHttp: true
        }),
        id = await sessions.createUser({
          login: "owner@fixture.test",
          password: "Owned-fixture-password-34!",
          role: "OWNER"
        });
      f.database.db.prepare("UPDATE organization_memberships SET role='VIEWER' WHERE user_id=?").run(id);
      const scope = recoveryScope({
        mode: "server",
        serverSessions: sessions,
        principal: { mode: "server", userId: id, role: "OWNER" },
        url: new URL("http://127.0.0.1/api/recovery-center"),
        request: { headers: {} },
        organizations: new OrganizationService(f.database)
      } as unknown as ApiContext);
      expect(scope).toMatchObject({
        canReview: false,
        canRecover: false,
        canManageWorkers: false,
        canRecompute: false
      });
    } finally {
      f.close();
    }
  });
});
