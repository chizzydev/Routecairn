import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { afterEach, describe, it, expect } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { workflowRecoveryFixture, closeRecoveryFixtures } from "../helpers/workflow-recovery-fixture.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
afterEach(closeRecoveryFixtures);
describe("cleanup authority is consumed once despite unsuccessful restoration", () => {
  it("does not silently replay the same failed checkpoint authorization", async () => {
    const identity = { principalId: "disposable-owner", tenantId: "fixture-tenant", role: "member" },
      f = await workflowRecoveryFixture("authenticationLifecycle", {
        authProfile: authProfileSchema.parse({ ...identity, headers: { authorization: "Bearer expired" } }),
        requiredAuthorization: "Bearer correct-fresh"
      }),
      handle = await startDashboardServer({
        dataDir: join(process.env.ROUTECAIRN_MUTATION_DIR!, "dashboard"),
        port: 0,
        masterKey: Buffer.alloc(32, 7).toString("base64url")
      });
    try {
      const token = new URL(handle.bootstrapUrl!).hash.slice(11),
        bootstrap = await fetch(handle.url + "/api/session/bootstrap", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        }),
        cookie = bootstrap.headers.get("set-cookie")!.split(";")[0]!,
        { csrfToken } = (await bootstrap.json()) as { csrfToken: string },
        headers = { cookie, origin: handle.url, "content-type": "application/json", "x-csrf-token": csrfToken };
      const tr = await fetch(handle.url + "/api/targets", {
        method: "POST",
        headers,
        body: JSON.stringify({
          displayName: "Owned failure fixture",
          baseOrigin: f.origin,
          tags: [],
          classification: "LOCAL",
          authorizationType: "OWNED",
          authorizationSummary: "Disposable cleanup only",
          approvedScope: f.scope,
          productionEnabled: false
        })
      });
      expect(tr.status).toBe(201);
      const { targetId } = (await tr.json()) as { targetId: string };
      const cr = await fetch(handle.url + "/api/credential-profiles", {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: "Fresh but rejected fixture actor",
          safeAlias: "fixture-owner",
          targetId,
          safeIdentitySummary: identity,
          secret: { authorizationHeader: "Bearer intentionally-rejected" }
        })
      });
      expect(cr.status).toBe(201);
      const { profileId } = (await cr.json()) as { profileId: string };
      const input = {
          caseId: f.checkpoint.caseId,
          checkpointDigest: f.checkpoint.digest,
          targetId,
          credentialProfileId: profileId,
          confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY"
        },
        first = await fetch(handle.url + "/api/workflow-mutations/recovery", {
          method: "POST",
          headers,
          body: JSON.stringify(input)
        });
      expect(first.status).toBe(202);
      const { jobId } = (await first.json()) as { jobId: string };
      await expect
        .poll(
          async () => {
            const r = await fetch(handle.url + "/api/workflow-mutations/status", { headers: { cookie } }),
              body = (await r.json()) as { jobs: Array<{ id: string; status: string }> };
            return body.jobs.find((j) => j.id === jobId)?.status;
          },
          { timeout: 20000 }
        )
        .toBe("CLEANUP_FAILED");
      const count = f.received.length,
        duplicate = await fetch(handle.url + "/api/workflow-mutations/recovery", {
          method: "POST",
          headers,
          body: JSON.stringify(input)
        });
      writeFileSync(
        join(process.env.ROUTECAIRN_MUTATION_DIR!, "REPLAY_AFTER_FAILED_RECEIPT.json"),
        JSON.stringify(
          {
            first: first.status,
            duplicate: duplicate.status,
            requestsBeforeDuplicate: count,
            requests: f.received,
            provenance: "ACTUAL_WINDOWS_WORKER_OWNED_LOOPBACK_ONLY"
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(duplicate.status).toBe(409);
    } finally {
      await handle.close();
    }
  });
});
