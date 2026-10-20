import { it, expect } from "vitest";
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
it("enforces authenticated observed-state history, reviews, scoped CA reads/runs/ack and CSRF", async () => {
  const f = await observedStateRegressionFixture("procurement");
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  try {
    const p = await f.prepare(),
      run = await f.ca.runNow(p.assurancePolicyId, "operator"),
      notice = f.ca.notifications()[0]!;
    await f.execution.shutdown();
    f.ca.shutdown();
    const publicOrigin = "https://owned-observed.fixture.test",
      sessionSecret = "disposable-observed-state-session-secret-at-least48characters",
      s = new ServerSessionManager(f.database, {
        publicOrigin,
        sessionSecret,
        trustProxy: true,
        developmentInsecureHttp: false
      }),
      owner = await s.createFirstOwner("owner@observed.test", "Disposable password 87!");
    await s.createUser({ login: "viewer@observed.test", password: "Disposable password 87!", role: "VIEWER" });
    const analyst = await s.createUser({
      login: "analyst@observed.test",
      password: "Disposable password 87!",
      role: "ANALYST"
    });
    f.database.db
      .prepare("UPDATE organization_memberships SET role='VIEWER' WHERE organization_id=? AND user_id=?")
      .run(f.org, analyst);
    const foreign = new OrganizationService(f.database).create(
      { name: "Foreign observations", slug: "foreign-observed" },
      owner
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
    const receipts: unknown[] = [],
      wire = f.wire.length,
      base = "/api/authorization-workbench/observed-state";
    for (const actor of ["owner", "viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { origin: publicOrigin, "content-type": "application/json", "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@observed.test", password: "Disposable password 87!" })
      });
      expect(login.status).toBe(200);
      const csrf = (await login.json()) as { csrfToken: string },
        headers = {
          cookie: login.headers.get("set-cookie")!.split(";")[0]!,
          origin: publicOrigin,
          "content-type": "application/json",
          "x-forwarded-proto": "https",
          "x-csrf-token": csrf.csrfToken
        };
      const request = async (path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) => {
        const r = await fetch(server!.url + path, {
          method,
          headers: { ...headers, ...extra },
          ...(body ? { body: JSON.stringify(body) } : {})
        });
        const text = await r.text();
        receipts.push({ actor, path, method, status: r.status, body: text });
        appendFileSync(
          join(f.root, "AUTHENTICATED_HTTP_RECEIPTS.jsonl"),
          JSON.stringify({ actor, path, method, status: r.status, body: text }) + "\n"
        );
        return { status: r.status, text };
      };
      for (const path of [
        base + "/policies",
        base + "/policies/" + p.policy.id,
        base + "/policies/" + p.policy.id + "/assessments",
        base + "/attention",
        base + "/assessments/" + (run.safeSummary as { observationAssessmentId: string }).observationAssessmentId
      ])
        expect((await request(path)).status).toBe(actor === "viewer" ? 403 : 200);
      const capabilities = await request(base + "/policies");
      if (actor !== "viewer") expect(JSON.parse(capabilities.text).canReviewPolicies).toBe(actor === "owner");
      const draft = { ...p.policy.snapshot.input, name: "HTTP successor observation policy", supersedes: p.policy.id };
      expect((await request(base + "/preview", "POST", draft)).status).toBe(actor === "owner" ? 200 : 403);
      if (actor === "owner") {
        for (const path of [
          base + "/policies/" + p.policy.id,
          "/api/continuous-assurance/policies/" + p.assurancePolicyId
        ])
          expect((await request(path, "GET", undefined, { "x-routecairn-organization-id": foreign })).status).toBe(404);
        const foreignList = await request("/api/continuous-assurance", "GET", undefined, {
          "x-routecairn-organization-id": foreign
        });
        expect(foreignList.status).toBe(200);
        expect(foreignList.text).not.toContain(p.assurancePolicyId);
        expect(foreignList.text).not.toContain(String(notice.id));
        expect(
          (
            await request(
              "/api/continuous-assurance/policies/" + p.assurancePolicyId + "/run",
              "POST",
              { confirmation: "I_CONFIRM_CONTINUOUS_ASSURANCE_RUN" },
              { "x-routecairn-organization-id": foreign }
            )
          ).status
        ).toBe(404);
        expect(
          (
            await request(
              "/api/continuous-assurance/notifications/" + notice.id + "/acknowledge",
              "POST",
              { confirmation: "I_ACKNOWLEDGE_CONTINUOUS_ASSURANCE_NOTIFICATION" },
              { "x-routecairn-organization-id": foreign }
            )
          ).status
        ).toBe(404);
        expect((await request(base + "/preview", "POST", draft, { "x-csrf-token": "invalid" })).status).toBe(401);
      } else
        expect(
          (
            await request("/api/continuous-assurance/policies/" + p.assurancePolicyId + "/run", "POST", {
              confirmation: "I_CONFIRM_CONTINUOUS_ASSURANCE_RUN"
            })
          ).status
        ).toBe(403);
    }
    expect(f.wire.length).toBe(wire);
    f.receipt("OBSERVED_STATE_REAL_AUTHENTICATED_HTTP", {
      receipts,
      wireBefore: wire,
      wireAfter: f.wire.length,
      p,
      run
    });
  } finally {
    await server?.close();
    await f.close();
  }
});
