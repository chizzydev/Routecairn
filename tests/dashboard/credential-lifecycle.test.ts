import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CredentialVault, parseVaultKey } from "../../src/dashboard/credentials/CredentialVault.js";
import { assertCredentialBindingsCurrent, evaluateCredentialReadiness } from "../../src/dashboard/credentials/CredentialReadiness.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const key = Buffer.alloc(32, 31).toString("base64url");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("credential lifecycle governance", () => {
  it("persists health history, enforces impact bindings, and versions renewal", () => {
    const { database, vault } = fixture();
    const id = vault.create(input({ expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString() }));
    expect(vault.getSummary(id)?.health.classification).toBe("UNVERIFIED");

    vault.recordHealth(id, "HEALTHY", "TEST", "VERIFIED", "Identity verified.", "principal-hash");
    expect(vault.getSummary(id)?.health.classification).toBe("NEAR_EXPIRY");
    expect(vault.healthTimeline(id).map((event) => event.classification)).toEqual(["NEAR_EXPIRY", "HEALTHY", "UNVERIFIED"]);

    const reviewed = vault.dependencies(id);
    new TargetRepository(database).create({ displayName: "Bound", baseOrigin: "http://127.0.0.1:4010", tags: [], classification: "LOCAL", authorizationType: "CONTROLLED_LAB", authorizationSummary: "Owned disposable test target", approvedScope: scope(4010), defaultCredentialProfileId: id });
    expect(() => vault.setEnabled(id, false, reviewed.impactDigest)).toThrow(/IMPACT_CHANGED/);

    const currentImpact = vault.dependencies(id);
    vault.setEnabled(id, false, currentImpact.impactDigest);
    expect(vault.getSummary(id)?.health.classification).toBe("DISABLED");
    const expired = vault.create(input({ safeAlias: "Expired", expiresAt: new Date(Date.now() - 1_000).toISOString() }));
    expect(vault.getSummary(expired)?.health).toMatchObject({ classification: "EXPIRED", reasonCode: "EXPIRY_REACHED" });
    expect(vault.healthTimeline(expired)[0]).toMatchObject({ classification: "EXPIRED" });
    vault.setEnabled(id, true, vault.dependencies(id).impactDigest);
    const beforeVersion = vault.getSummary(id)!.secretVersion;
    const approvedBinding = [{ id, role: "single" as const, secretVersion: beforeVersion, healthClassification: vault.getSummary(id)!.health.classification }];
    vault.renew(id, { secret: { authorizationHeader: "Bearer replacement" }, expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), impactDigest: vault.dependencies(id).impactDigest });
    expect(vault.getSummary(id)).toMatchObject({ secretVersion: beforeVersion + 1, health: { classification: "UNVERIFIED", reasonCode: "RENEWED_RETEST_REQUIRED" } });
    expect(vault.decryptForUse(id).authorizationHeader).toBe("Bearer replacement");
    expect(() => assertCredentialBindingsCurrent(vault, approvedBinding)).toThrow(/CHANGED_AFTER_QUEUE/);
    database.close();
  });

  it("blocks a credential that cannot remain valid for the complete scan window and warns about account-pair drift", () => {
    const { database, vault } = fixture();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const a = vault.create(input({ safeAlias: "A", expiresAt, principalId: "same" }));
    const b = vault.create(input({ safeAlias: "B", expiresAt: new Date(Date.now() + 86_400_000).toISOString(), principalId: "same" }));
    vault.recordHealth(a, "HEALTHY", "TEST", "VERIFIED", "Identity verified.", "same-hash");
    vault.recordHealth(b, "HEALTHY", "TEST", "VERIFIED", "Identity verified.", "same-hash");
    const readiness = evaluateCredentialReadiness(vault, {
      target: "http://127.0.0.1:4010",
      scopeFile: "unused.json",
      profile: "quick",
      credentialProfileAId: a,
      credentialProfileBId: b
    }, 120_000);
    expect(readiness.ready).toBe(false);
    expect(readiness.blockers.some((blocker) => blocker.code === "CREDENTIAL_EXPIRES_DURING_SCAN")).toBe(true);
    expect(readiness.warnings.map((warning) => warning.code)).toEqual(expect.arrayContaining(["ACCOUNT_PAIR_DECLARED_IDENTITY_COLLISION", "ACCOUNT_PAIR_VERIFIED_IDENTITY_COLLISION"]));
    database.close();
  });

  it("surfaces expiring-during-execution as a dashboard plan-preview blocker", async () => {
    const { database, vault, directory } = fixture();
    const profileId = vault.create(input({ expiresAt: new Date(Date.now() + 60_000).toISOString() }));
    const scopePath = join(directory, "scope.json");
    writeFileSync(scopePath, JSON.stringify(scope(4010)));
    const service = new ScanExecutionService(database, resolveDashboardPaths(directory), vault);
    try {
      const preview = await service.preview({ target: "http://127.0.0.1:4010", scopeFile: scopePath, profile: "quick", credentialProfileId: profileId });
      expect(preview.credentialReadiness.ready).toBe(false);
      expect(preview.credentialReadiness.blockers).toContainEqual(expect.objectContaining({ code: "CREDENTIAL_EXPIRES_DURING_SCAN" }));
    } finally {
      await service.shutdown();
      database.close();
    }
  });

  it("uses the approved target scope for a real identity health check and classifies identity drift", async () => {
    let principal = "account-a";
    let statusCode = 200;
    const server = createServer((_request, response) => {
      response.writeHead(statusCode, { "content-type": "application/json" });
      response.end(JSON.stringify({ user: { id: principal, tenant: "tenant-a", role: "analyst" } }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Fixture did not bind.");
    const { database, vault, directory } = fixture();
    const targetId = new TargetRepository(database).create({ displayName: "Identity fixture", baseOrigin: `http://127.0.0.1:${address.port}`, tags: [], classification: "LOCAL", authorizationType: "CONTROLLED_LAB", authorizationSummary: "Owned disposable identity fixture", approvedScope: scope(address.port) });
    const profileId = vault.create(input({ targetId, principalId: "account-a", expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(), identityEndpoint: `http://127.0.0.1:${address.port}/me` }));
    const service = new ScanExecutionService(database, resolveDashboardPaths(directory), vault);
    try {
      const healthy = await service.testCredentialProfile(profileId, targetId);
      expect(healthy.health).toMatchObject({ classification: "HEALTHY" });
      principal = "account-b";
      const mismatch = await service.testCredentialProfile(profileId, targetId);
      expect(mismatch.health).toMatchObject({ classification: "IDENTITY_MISMATCH", reasonCode: "PRINCIPAL_MISMATCH" });
      statusCode = 401;
      const invalid = await service.testCredentialProfile(profileId, targetId);
      expect(invalid.health).toMatchObject({ classification: "INVALID", reasonCode: "AUTHENTICATION_FAILED" });
      expect(JSON.stringify(vault.healthTimeline(profileId))).not.toContain("account-a");
      expect(JSON.stringify(vault.healthTimeline(profileId))).not.toContain("account-b");
    } finally {
      await service.shutdown();
      database.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

function fixture(): { directory: string; database: DashboardDatabase; vault: CredentialVault } {
  const directory = mkdtempSync(join(tmpdir(), "routecairn-credential-lifecycle-"));
  temporaryDirectories.push(directory);
  const database = new DashboardDatabase(join(directory, "dashboard.sqlite"));
  database.migrate();
  return { directory, database, vault: new CredentialVault(database, parseVaultKey(key, "1")) };
}

function input(overrides: { safeAlias?: string; targetId?: string; expiresAt?: string; principalId?: string; identityEndpoint?: string } = {}) {
  return {
    name: overrides.safeAlias ?? "Disposable account",
    safeAlias: overrides.safeAlias ?? "Account A",
    ...(overrides.targetId ? { targetId: overrides.targetId } : {}),
    ...(overrides.expiresAt ? { expiresAt: overrides.expiresAt } : {}),
    safeIdentitySummary: { principalId: overrides.principalId ?? "account-a", tenantId: "tenant-a", role: "analyst" },
    secret: {
      authorizationHeader: "Bearer original",
      ...(overrides.identityEndpoint ? { identityVerification: { endpoint: overrides.identityEndpoint, principalFieldPath: "user.id", tenantFieldPath: "user.tenant", roleFieldPath: "user.role" } } : {})
    }
  };
}

function scope(port: number) {
  return { program: "Credential lifecycle fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 2, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Test", allowedPorts: [port] };
}
