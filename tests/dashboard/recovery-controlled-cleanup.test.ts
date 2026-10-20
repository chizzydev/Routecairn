import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ControlledMutationApprovalRepository } from "../../src/dashboard/db/ControlledMutationApprovalRepository.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { exampleScope } from "../../src/config/defaults.js";
const sha = (v: string) => createHash("sha256").update(v).digest("hex");
describe.skipIf(process.platform !== "win32")("bound operator cleanup through native Windows worker", () => {
  it("restores only the bound disposable object and retains encrypted evidence", async () => {
    const root = createOwnedTestDirectory("recovery-controlled-api-"),
      paths = resolveDashboardPaths(root),
      requests: string[] = [];
    let restored = false;
    const targetServer = createServer((req, res) => {
      requests.push(req.method + " " + req.url);
      if (req.headers.authorization !== "Bearer fresh-fixture") return res.writeHead(401).end();
      res.setHeader("content-type", "application/json");
      if (req.url === "/rollback" && req.method === "POST") {
        restored = true;
        return res.writeHead(204).end();
      }
      if (req.url === "/identity") return res.end(JSON.stringify({ object: "fixture-object" }));
      if (req.url === "/state") return res.end(JSON.stringify({ restored }));
      return res.writeHead(500).end();
    });
    await new Promise<void>((r) => targetServer.listen(0, "127.0.0.1", r));
    const origin = "http://127.0.0.1:" + (targetServer.address() as { port: number }).port;
    const handle = await startDashboardServer({
        dataDir: root,
        port: 0,
        masterKey: Buffer.alloc(32, 9).toString("base64url")
      }),
      database = new DashboardDatabase(paths.databasePath);
    database.migrate();
    try {
      const token = new URL(handle.bootstrapUrl!).hash.slice("#bootstrap=".length),
        auth = await fetch(handle.url + "/api/session/bootstrap", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        }),
        cookie = auth.headers.get("set-cookie")!.split(";")[0]!,
        { csrfToken } = (await auth.json()) as { csrfToken: string },
        headers = { cookie, origin: handle.url, "content-type": "application/json", "x-csrf-token": csrfToken };
      const scope = scopeSchema.parse({
          ...exampleScope,
          allowedDomains: ["127.0.0.1"],
          allowedMethods: ["GET", "POST"],
          disallowedPaths: []
        }),
        targets = new TargetRepository(database),
        targetId = targets.create({
          displayName: "Disposable bound restoration",
          baseOrigin: origin,
          tags: [],
          classification: "LOCAL",
          authorizationType: "OWNED",
          authorizationSummary: "Owned loopback restoration fixture only",
          approvedScope: scope,
          productionEnabled: false
        }),
        target = targets.get(targetId)!;
      const profile = await fetch(handle.url + "/api/credential-profiles", {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: "Fresh fixture owner",
          safeAlias: "fixture-owner",
          targetId,
          safeIdentitySummary: { principalId: "fixture-owner" },
          secret: { authorizationHeader: "Bearer fresh-fixture" }
        })
      });
      expect(profile.status).toBe(201);
      const { profileId } = (await profile.json()) as { profileId: string };
      const binding = {
          targetIdentityFingerprint: sha(`${target.id}:${target.rowVersion}:${origin}`),
          scopeDigest: sha(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())),
          planIdentity: "a".repeat(64)
        },
        caseId = "owned-controlled-cleanup",
        approvals = new ControlledMutationApprovalRepository(database),
        approvalId = approvals.create({
          caseId,
          targetId,
          targetOrigin: origin,
          ...binding,
          authorizationSummary: "Synthetic cleanup only",
          expiresAt: "2099-01-01T00:00:00.000Z"
        });
      approvals.approve(approvalId, "local-operator");
      database.db
        .prepare("UPDATE controlled_mutation_approvals SET status='CLEANUP_REQUIRED' WHERE id=?")
        .run(approvalId);
      const identityFingerprint = sha(JSON.stringify("fixture-object")),
        vault = new MutationRecoveryVault(paths.mutationJournalDir, true),
        bundlePath = await vault.seal({
          caseId,
          targetOrigin: origin,
          approvalBinding: binding,
          authorizationExpiresAt: "2099-01-01T00:00:00.000Z",
          targetIdentityFingerprint: identityFingerprint,
          targetIdentityVerification: {
            request: { url: origin + "/identity", method: "GET" },
            assertions: [{ path: "object", operator: "EQUALS", expectedValue: "fixture-object" }],
            attempts: 1,
            delayMs: 0
          },
          rollbackRequest: {
            url: origin + "/rollback",
            method: "POST",
            body: "{}",
            headers: { authorization: "Bearer expired-fixture" }
          },
          rollbackVerification: {
            request: { url: origin + "/state", method: "GET" },
            assertions: [{ path: "restored", operator: "EQUALS", expectedValue: true }],
            attempts: 1,
            delayMs: 0
          }
        }),
        before = readFileSync(bundlePath);
      await new MutationJournal(join(paths.mutationJournalDir, "mutation-journal.json")).append({
        caseId,
        stage: "CLEANUP_REQUIRED",
        mode: "CONTROLLED_MUTATION",
        targetOrigin: origin,
        targetIdentityFingerprint: identityFingerprint
      });
      const inventory = await fetch(handle.url + "/api/recovery-center?kind=CLEANUP", { headers: { cookie } }),
        body = (await inventory.json()) as {
          issues: Array<{ subjectId: string; snapshotDigest: string; actions: { cleanup: boolean } }>;
        },
        issue = body.issues.find((i) => i.subjectId === "approval:" + approvalId)!;
      expect(issue.actions.cleanup).toBe(true);
      const input = {
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        credentialProfileId: profileId,
        confirmation: "I_AUTHORIZE_BOUND_CONTROLLED_CLEANUP_ONLY"
      };
      const noCsrf = await fetch(handle.url + "/api/recovery-center/controlled-cleanup", {
        method: "POST",
        headers: { cookie, "content-type": "application/json" },
        body: JSON.stringify(input)
      });
      expect([401, 403]).toContain(noCsrf.status);
      const stale = await fetch(handle.url + "/api/recovery-center/controlled-cleanup", {
        method: "POST",
        headers,
        body: JSON.stringify({ ...input, snapshotDigest: "0".repeat(64) })
      });
      expect(stale.status).toBe(409);
      expect(requests).toEqual([]);
      const queued = await fetch(handle.url + "/api/recovery-center/controlled-cleanup", {
        method: "POST",
        headers,
        body: JSON.stringify(input)
      });
      expect(queued.status).toBe(202);
      await expect.poll(() => approvals.get(approvalId)?.status, { timeout: 20000 }).toBe("COMPLETED");
      expect(requests).toEqual(["GET /identity", "POST /rollback", "GET /state"]);
      expect(readFileSync(bundlePath)).toEqual(before);
      writeFileSync(
        join(root, "CONTROLLED_CLEANUP_NATIVE_RECEIPT.json"),
        JSON.stringify(
          {
            requests,
            approval: approvals.get(approvalId),
            bundleSha256: sha(before.toString()),
            retainedByteIdentical: true,
            integrity: database.db.pragma("integrity_check"),
            foreignKeys: database.db.pragma("foreign_key_check"),
            resources: database.db.prepare("SELECT * FROM worker_resources").all()
          },
          null,
          2
        ),
        { flag: "wx" }
      );
    } finally {
      await handle.close();
      database.close();
      targetServer.closeAllConnections();
      await new Promise<void>((r) => targetServer.close(() => r()));
      retainOwnedTestDirectory(root);
    }
  });
});
