import { randomUUID } from "node:crypto";
import { describe, it, expect } from "vitest";
import { cleanupAttemptFixture } from "../helpers/cleanup-attempt-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
describe("real cleanup attempt HTTP lifecycle", () => {
  it("deduplicates concurrent requests and completed lost acknowledgements with scoped read-only history", async () => {
    const f = await cleanupAttemptFixture(),
      server = await startDashboardServer({
        dataDir: f.root,
        port: 0,
        masterKey: Buffer.alloc(32, 6).toString("base64url")
      });
    try {
      const token = new URL(server.bootstrapUrl!).hash.slice(11),
        auth = await fetch(server.url + "/api/session/bootstrap", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        }),
        cookie = auth.headers.get("set-cookie")!.split(";")[0]!,
        { csrfToken } = (await auth.json()) as { csrfToken: string },
        headers = { cookie, origin: server.url, "content-type": "application/json", "x-csrf-token": csrfToken };
      const inventory = (await (
          await fetch(server.url + "/api/recovery-center?kind=CLEANUP", { headers: { cookie } })
        ).json()) as { issues: Array<{ subjectId: string; snapshotDigest: string }> },
        issue = inventory.issues.find((i) => i.subjectId === "approval:" + f.input.approvalId)!,
        input = {
          subjectId: issue.subjectId,
          snapshotDigest: issue.snapshotDigest,
          credentialProfileId: f.input.credentialProfileId,
          requestId: randomUUID(),
          confirmation: "I_AUTHORIZE_BOUND_CONTROLLED_CLEANUP_ONLY"
        };
      const responses = await Promise.all(
        [1, 2].map(() =>
          fetch(server.url + "/api/recovery-center/controlled-cleanup", {
            method: "POST",
            headers,
            body: JSON.stringify(input)
          })
        )
      );
      expect(responses.map((r) => r.status)).toEqual([202, 202]);
      const a = (await responses[0]!.json()) as { attemptId: string },
        b = (await responses[1]!.json()) as { attemptId: string };
      expect(b.attemptId).toBe(a.attemptId);
      await expect
        .poll(
          async () => {
            const r = await fetch(server.url + "/api/recovery-center/attempts/" + a.attemptId, { headers: { cookie } });
            return ((await r.json()) as { phase: string }).phase;
          },
          { timeout: 20000 }
        )
        .toBe("RESTORATION_VERIFIED");
      const duplicate = await fetch(server.url + "/api/recovery-center/controlled-cleanup", {
        method: "POST",
        headers,
        body: JSON.stringify(input)
      });
      expect(duplicate.status).toBe(202);
      expect(await duplicate.json()).toMatchObject({
        attemptId: a.attemptId,
        alreadyRecorded: true,
        restorationVerified: false
      });
      expect(f.requests).toEqual(["GET /identity", "POST /rollback", "GET /state"]);
      const other = new OrganizationService(f.database).create(
          { name: "Other fixture", slug: "other-" + randomUUID() },
          "local-operator"
        ),
        cross = await fetch(server.url + "/api/recovery-center/attempts/" + a.attemptId, {
          headers: { cookie, "x-routecairn-organization-id": other }
        });
      expect(cross.status).toBe(404);
      const forged = await fetch(server.url + "/api/recovery-center/controlled-cleanup", {
        method: "POST",
        headers,
        body: JSON.stringify({ ...input, clearQuarantine: true })
      });
      expect(forged.status).toBe(400);
      f.capture("HTTP_IDEMPOTENCY_AND_SCOPING");
    } finally {
      await server.close();
      await f.close();
    }
  });
});
