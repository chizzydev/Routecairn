import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { workflowRecoveryFixture, closeRecoveryFixtures } from "../helpers/workflow-recovery-fixture.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";

afterEach(closeRecoveryFixtures);
describe("dashboard-first cleanup recovery API and isolated worker", () => {
  it("authorizes a stored checkpoint through the API and verifies cleanup through a real worker", async () => {
    const identity = { principalId: "disposable-owner", tenantId: "fixture-tenant", role: "member" };
    const fixture = await workflowRecoveryFixture("authenticationLifecycle", { caseId: "a".repeat(115), authProfile: authProfileSchema.parse({ ...identity, headers: { authorization: "Bearer expired-original" } }), requiredAuthorization: "Bearer fresh-recovery" });
    const handle = await startDashboardServer({ dataDir: join(process.env.ROUTECAIRN_MUTATION_DIR!, "dashboard"), port: 0, masterKey: Buffer.alloc(32, 7).toString("base64url") });
    try {
      const token = new URL(handle.bootstrapUrl!).hash.replace("#bootstrap=", "");
      const bootstrap = await fetch(`${handle.url}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
      expect(bootstrap.status).toBe(200);
      const cookie = bootstrap.headers.get("set-cookie")!.split(";")[0]!;
      const { csrfToken } = await bootstrap.json() as { csrfToken: string };
      const headers = { cookie, "content-type": "application/json", "x-csrf-token": csrfToken, origin: handle.url };
      const targetResponse = await fetch(`${handle.url}/api/targets`, { method: "POST", headers, body: JSON.stringify({ displayName: "Disposable cleanup target", baseOrigin: fixture.origin, tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Owned localhost recovery fixture", approvedScope: fixture.scope, productionEnabled: false }) });
      expect(targetResponse.status).toBe(201);
      const { targetId } = await targetResponse.json() as { targetId: string };
      const credentialResponse = await fetch(`${handle.url}/api/credential-profiles`, { method: "POST", headers, body: JSON.stringify({ name: "Fresh recovery actor", safeAlias: "recovery-owner", targetId, safeIdentitySummary: identity, secret: { authorizationHeader: "Bearer fresh-recovery" } }) });
      expect(credentialResponse.status).toBe(201);
      const { profileId: credentialProfileId } = await credentialResponse.json() as { profileId: string };
      const inventoryResponse = await fetch(`${handle.url}/api/workflow-mutations/status`, { headers: { cookie } });
      expect(inventoryResponse.status).toBe(200);
      const raw = await inventoryResponse.text(); expect(raw).not.toContain("captured-restoration-sentinel");
      const inventory = JSON.parse(raw);
      expect(inventory.cases[0]).toMatchObject({ recoveryKind: "WORKFLOW", workflow: "authenticationLifecycle", cleanupOnly: true });
      const input = { caseId: fixture.checkpoint.caseId, checkpointDigest: fixture.checkpoint.digest, targetId, credentialProfileId, confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY" };
      const noCsrf = await fetch(`${handle.url}/api/workflow-mutations/recovery`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify(input) });
      expect([401, 403]).toContain(noCsrf.status);
      const changed = await fetch(`${handle.url}/api/workflow-mutations/recovery`, { method: "POST", headers, body: JSON.stringify({ ...input, checkpointDigest: "0".repeat(64) }) });
      expect(changed.status).toBe(409); expect(fixture.received).toEqual([]);
      const queued = await fetch(`${handle.url}/api/workflow-mutations/recovery`, { method: "POST", headers, body: JSON.stringify(input) });
      expect(queued.status).toBe(202);
      const { jobId } = await queued.json() as { jobId: string };
      const duplicate = await fetch(`${handle.url}/api/workflow-mutations/recovery`, { method: "POST", headers, body: JSON.stringify(input) });
      expect(duplicate.status).toBe(409);
      await expect.poll(async () => {
        const response = await fetch(`${handle.url}/api/workflow-mutations/status`, { headers: { cookie } });
        const body = await response.json() as { jobs: Array<{ id: string; status: string }> };
        return body.jobs.find((job) => job.id === jobId)?.status;
      }, { timeout: 60000, interval: 100 }).toBe("ROLLBACK_VERIFIED");
      expect(fixture.received).toEqual(["POST /fixture/cleanup", "GET /state"]);
      const final = await fetch(`${handle.url}/api/workflow-mutations/status`, { headers: { cookie } });
      expect((await final.json() as { cleanupRequired: number }).cleanupRequired).toBe(0);
    } finally { await handle.close(); }
  }, 90000);
});
