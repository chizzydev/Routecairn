import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import type { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
it("enforces real session and organization permission at both transition source/review boundaries", async () => {
  const f = await transitionApplicationFixture("procurement");
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  const receipts: unknown[] = [];
  try {
    const before = await f.acquire(),
      event = await f.apply("account-a"),
      after = await f.acquire();
    await f.execution.shutdown();
    const publicOrigin = "https://owned-transition.fixture.test",
      sessionSecret = "owned-transition-session-secret-at-least-48-characters",
      sessions = new ServerSessionManager(f.database, {
        publicOrigin,
        sessionSecret,
        trustProxy: true,
        developmentInsecureHttp: false
      });
    const owner = await sessions.createFirstOwner("owner@transition.test", "Disposable password 87!");
    await sessions.createUser({ login: "viewer@transition.test", password: "Disposable password 87!", role: "VIEWER" });
    const analyst = await sessions.createUser({
      login: "analyst@transition.test",
      password: "Disposable password 87!",
      role: "ANALYST"
    });
    f.database.db
      .prepare("UPDATE organization_memberships SET role='VIEWER' WHERE organization_id=? AND user_id=?")
      .run(f.org, analyst);
    const orgs = new OrganizationService(f.database),
      foreign = orgs.create({ name: "Foreign transition", slug: "foreign-transition" }, owner);
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
      input = {
        mapRevisionId: after.revision.revisionId,
        workflow: f.workflow,
        transition: f.declaration(before.revision.revisionId, event, "FORBIDDEN")
      };
    let proposal: ReturnType<ApplicationHypothesisService["generate"]> | undefined;
    for (const actor of ["owner", "viewer", "analyst"]) {
      const login = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", origin: publicOrigin, "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: actor + "@transition.test", password: "Disposable password 87!" })
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
      const create = await fetch(server.url + base, { method: "POST", headers, body: JSON.stringify(input) });
      receipts.push({ actor, method: "POST", operation: "GENERATE_TRANSITION", status: create.status });
      expect(create.status).toBe(actor === "owner" ? 201 : 403);
      if (actor === "owner") {
        proposal = (await create.json()) as typeof proposal;
        const wrong = await fetch(server.url + base, {
          method: "POST",
          headers,
          body: JSON.stringify({
            ...input,
            transition: { ...input.transition, beforeMapRevisionId: "00000000-0000-4000-8000-000000000000" }
          })
        });
        expect(wrong.status).toBe(404);
        receipts.push({ actor, operation: "WRONG_BEFORE_SOURCE", status: wrong.status });
        const scoped = await fetch(server.url + base + "/" + proposal!.proposalId, {
          headers: { ...headers, "x-routecairn-organization-id": foreign }
        });
        expect(scoped.status).toBe(404);
      }
      const read = await fetch(server.url + base + "/" + proposal!.proposalId, { headers });
      receipts.push({ actor, operation: "READ_HISTORY", status: read.status });
      expect(read.status).toBe(actor === "viewer" ? 403 : 200);
      const review = await fetch(server.url + base + "/" + proposal!.proposalId + "/decisions", {
        method: "POST",
        headers,
        body: JSON.stringify(f.transitionReviewFor(proposal!))
      });
      receipts.push({ actor, operation: "REVIEW_TRANSITION", status: review.status });
      expect(review.status).toBe(actor === "owner" ? 201 : 403);
    }
    const h = f.hypotheses.get(f.org, proposal!.proposalId);
    expect(h.decisions).toHaveLength(1);
    expect(h.matrices).toHaveLength(1);
    expect(f.wire.filter((v) => !v.path.startsWith("/target-events/")).length).toBe(24);
    writeFileSync(
      join(f.root, "TRANSITION_REAL_AUTHENTICATED_HTTP.json"),
      JSON.stringify(
        {
          receipts,
          targetRequestsOnlyNativeObservations: 24,
          targetJournalRead: 1,
          newTargetRequestsFromProposalReview: 0,
          authenticatedSessions: true,
          foreignScopeReturns404: true,
          productionPermissionBypass: false
        },
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
