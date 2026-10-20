import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { randomUUID, createHash } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ControlledMutationApprovalRepository } from "../../src/dashboard/db/ControlledMutationApprovalRepository.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { exampleScope } from "../../src/config/defaults.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { ControlledMutationRecoveryService } from "../../src/dashboard/execution/ControlledMutationRecoveryService.js";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
export async function cleanupAttemptFixture(options: { holdRollbackResponse?: boolean } = {}) {
  const root = createOwnedTestDirectory("cleanup-attempt-native-"),
    paths = resolveDashboardPaths(root),
    database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  const requests: string[] = [];
  let restored = false;
  const server = createServer((req, res) => {
    requests.push(req.method + " " + req.url);
    if (req.headers.authorization !== "Bearer fixture-fresh") return res.writeHead(401).end();
    res.setHeader("content-type", "application/json");
    if (req.url === "/rollback" && req.method === "POST") {
      restored = true;
      if (options.holdRollbackResponse) return;
      return res.writeHead(204).end();
    }
    return res.end(JSON.stringify({ object: "fixture-object", restored }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as { port: number }).port,
    scope = scopeSchema.parse({
      ...exampleScope,
      allowedDomains: ["127.0.0.1"],
      allowedMethods: ["GET", "POST"],
      disallowedPaths: []
    }),
    targets = new TargetRepository(database),
    targetId = targets.create({
      displayName: "Owned cleanup fixture",
      baseOrigin: origin,
      tags: [],
      classification: "LOCAL",
      authorizationType: "OWNED",
      authorizationSummary: "Generated disposable loopback cleanup fixture",
      approvedScope: scope,
      productionEnabled: false
    }),
    target = targets.get(targetId)!,
    vault = new CredentialVault(database, { bytes: Buffer.alloc(32, 6), version: "1" });
  const credentialProfileId = vault.create({
      name: "Fresh fixture",
      safeAlias: "fixture-owner",
      targetId,
      safeIdentitySummary: { principalId: "fixture-owner" },
      secret: { authorizationHeader: "Bearer fixture-fresh" }
    }),
    caseId = "cleanup-" + randomUUID(),
    binding = {
      planIdentity: "a".repeat(64),
      targetIdentityFingerprint: hash(`${targetId}:${target.rowVersion}:${origin}`),
      scopeDigest: hash(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort()))
    },
    approvals = new ControlledMutationApprovalRepository(database),
    approvalId = approvals.create({
      caseId,
      targetId,
      targetOrigin: origin,
      ...binding,
      authorizationSummary: "Fresh cleanup only",
      expiresAt: "2099-01-01T00:00:00.000Z"
    });
  approvals.approve(approvalId, "local-operator");
  database.db.prepare("UPDATE controlled_mutation_approvals SET status='CLEANUP_REQUIRED' WHERE id=?").run(approvalId);
  const identity = hash(JSON.stringify("fixture-object")),
    bundlePath = await new MutationRecoveryVault(paths.mutationJournalDir, true).seal({
      caseId,
      targetOrigin: origin,
      approvalBinding: binding,
      authorizationExpiresAt: "2099-01-01T00:00:00.000Z",
      targetIdentityFingerprint: identity,
      targetIdentityVerification: {
        request: { url: origin + "/identity", method: "GET" },
        assertions: [{ path: "object", operator: "EQUALS", expectedValue: "fixture-object" }],
        attempts: 1,
        delayMs: 0
      },
      rollbackRequest: { url: origin + "/rollback", method: "POST", body: "{}" },
      rollbackVerification: {
        request: { url: origin + "/state", method: "GET" },
        assertions: [{ path: "restored", operator: "EQUALS", expectedValue: true }],
        attempts: 1,
        delayMs: 0
      }
    });
  await new MutationJournal(join(paths.mutationJournalDir, "mutation-journal.json")).append({
    caseId,
    stage: "CLEANUP_REQUIRED",
    mode: "CONTROLLED_MUTATION",
    targetOrigin: origin,
    targetIdentityFingerprint: identity
  });
  const input: Parameters<ControlledMutationRecoveryService["startRecovery"]>[0] = {
    recoveryJobId: randomUUID(),
    requestId: randomUUID(),
    requestedBy: "local-operator",
    approvalId,
    bundlePath,
    caseId,
    targetId,
    credentialProfileId,
    workerRequest: {
      target: origin,
      targetId,
      profile: "authenticated" as const,
      credentialProfileId,
      recoveryScope: scope,
      studio: {
        version: 1 as const,
        scanName: "Owned cleanup",
        authorization: { category: "OWNED" as const, confirmed: true },
        scope,
        authentication: { mode: "primary" as const, primary: { source: "saved" as const, credentialProfileId } },
        outputs: { json: true, markdown: true, html: true },
        moduleSettings: {},
        workflows: [],
        workflowSummary: []
      }
    }
  };
  const services: ControlledMutationRecoveryService[] = [];
  const service = () => {
    const s = new ControlledMutationRecoveryService(database, paths, targets, vault);
    services.push(s);
    return s;
  };
  const capture = (name: string) =>
    writeFileSync(
      join(root, name + ".json"),
      JSON.stringify(
        {
          provenance: "ACTUAL_NATIVE_SQLITE_WINDOWS_WORKERS_OWNED_LOOPBACK",
          requests,
          restored,
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check"),
          attempts: database.db.prepare("SELECT * FROM cleanup_attempts").all(),
          events: database.db.prepare("SELECT * FROM cleanup_attempt_events ORDER BY attempt_id,sequence").all(),
          resources: database.db.prepare("SELECT * FROM worker_resources").all(),
          approvals: database.db
            .prepare("SELECT id,status,recovery_error_summary FROM controlled_mutation_approvals")
            .all()
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    root,
    paths,
    database,
    targets,
    vault,
    input,
    requests,
    service,
    organizationId: target.organizationId,
    capture,
    async close() {
      try {
        await Promise.allSettled(services.map((s) => s.shutdown()));
        capture("NATIVE_SQLITE_RECEIPT");
      } finally {
        database.close();
        server.closeAllConnections();
        await new Promise<void>((r) => server.close(() => r()));
        retainOwnedTestDirectory(root);
      }
    }
  };
}
