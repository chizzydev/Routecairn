import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { CredentialVault, parseVaultKey } from "../../src/dashboard/credentials/CredentialVault.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const secretValue = "Bearer routecairn-super-secret-token";
const keyA = Buffer.from("a".repeat(32)).toString("base64url");
const keyB = Buffer.from("b".repeat(32)).toString("base64url");

describe("dashboard credential vault", () => {
  it("is disabled without a master key and validates key length", () => {
    const dir = tempDir("routecairn-vault-disabled-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, undefined);
      expect(vault.status().enabled).toBe(false);
      expect(() => vault.create(profileInput())).toThrow(/not enabled/);
      expect(() => parseVaultKey(Buffer.from("short").toString("base64url"))).toThrow(/32 bytes/);
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("encrypts profiles without storing plaintext and decrypts only with the correct key", () => {
    const dir = tempDir("routecairn-vault-encrypt-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const first = vault.create(profileInput("first"));
      const second = vault.create(profileInput("second"));
      const rows = database.db.prepare("SELECT id, nonce, ciphertext, auth_tag FROM credential_profiles ORDER BY created_at ASC").all() as Array<{ id: string; nonce: string; ciphertext: string; auth_tag: string }>;
      expect(rows).toHaveLength(2);
      expect(rows[0]!.nonce).not.toBe(rows[1]!.nonce);
      expect(JSON.stringify(rows)).not.toContain(secretValue);
      expect(vault.list()[0]).not.toHaveProperty("ciphertext");
      expect(vault.decryptForUse(first).authorizationHeader).toBe(secretValue);
      expect(() => new CredentialVault(database, parseVaultKey(keyB, "1")).decryptForUse(first)).toThrow();
      database.db.prepare("UPDATE credential_profiles SET ciphertext = ? WHERE id = ?").run(`${rows[0]!.ciphertext.slice(0, -2)}AA`, first);
      expect(() => vault.decryptForUse(first)).toThrow();
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("keeps browser bootstrap secrets encrypted and returns only safe profile metadata", () => {
    const dir = tempDir("routecairn-vault-browser-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const browserPassword = "vault-browser-password";
      const id = vault.create({
        name: "Browser account",
        safeAlias: "browser-account",
        safeIdentitySummary: { principalId: "principal-a" },
        secret: {
          browserBootstrap: {
            schemaVersion: 1,
            loginSecrets: { password: browserPassword },
            login: { startUrl: "https://app.example.test/login", allowedWritePaths: ["/session"], successUrlPrefix: "https://app.example.test/app", steps: [{ action: "fill", selector: "#password", valueRef: "password" }] },
            journeys: [],
            proofCases: []
          }
        }
      });
      const row = database.db.prepare("SELECT ciphertext FROM credential_profiles WHERE id = ?").get(id) as { ciphertext: string };
      expect(JSON.stringify(row)).not.toContain(browserPassword);
      expect(JSON.stringify(vault.getSummary(id))).not.toContain(browserPassword);
      expect(vault.getSummary(id)?.credentialTypeSummary).toContain("browser-bootstrap");
      expect(vault.decryptForUse(id).browserBootstrap?.loginSecrets.password).toBe(browserPassword);
      database.close();
    } finally { cleanup(dir); }
  });

  it("keeps lifecycle secret references encrypted and exposes only their count in safe type metadata", () => {
    const dir = tempDir("routecairn-vault-lifecycle-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const lifecyclePassword = "vault-lifecycle-password";
      const id = vault.create({ name: "Lifecycle account", safeAlias: "disposable-member", safeIdentitySummary: {}, secret: { lifecycleSecrets: { username: "disposable@example.test", password: lifecyclePassword } } });
      const row = database.db.prepare("SELECT ciphertext FROM credential_profiles WHERE id = ?").get(id) as { ciphertext: string };
      expect(JSON.stringify(row)).not.toContain(lifecyclePassword);
      expect(JSON.stringify(vault.getSummary(id))).not.toContain(lifecyclePassword);
      expect(vault.getSummary(id)?.credentialTypeSummary).toContain("2-lifecycle-secret(s)");
      expect(vault.decryptForUse(id).lifecycleSecrets?.password).toBe(lifecyclePassword);
      database.close();
    } finally { cleanup(dir); }
  });

  it("binds ciphertext to profile ID, installation ID, and key version through associated data", () => {
    const dir = tempDir("routecairn-vault-ad-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const profileId = vault.create(profileInput());
      database.db.prepare("UPDATE credential_profiles SET key_version = '2' WHERE id = ?").run(profileId);
      expect(() => vault.decryptForUse(profileId)).toThrow();
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("rotates encrypted profiles to a new key version without exposing plaintext", () => {
    const dir = tempDir("routecairn-vault-rotate-");
    try {
      const database = openDatabase(dir);
      const currentVault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const profileId = currentVault.create(profileInput());
      const rotated = currentVault.rotateKey(parseVaultKey(keyB, "2")!);
      expect(rotated).toBe(1);
      const row = database.db.prepare("SELECT key_version, ciphertext FROM credential_profiles WHERE id = ?").get(profileId) as { key_version: string; ciphertext: string };
      expect(row.key_version).toBe("2");
      expect(JSON.stringify(row)).not.toContain(secretValue);
      expect(() => currentVault.decryptForUse(profileId)).toThrow();
      expect(new CredentialVault(database, parseVaultKey(keyB, "2")).decryptForUse(profileId).authorizationHeader).toBe(secretValue);
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("refuses disabled and deleted profiles during credential use", () => {
    const dir = tempDir("routecairn-vault-use-state-");
    try {
      const database = openDatabase(dir);
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const disabledId = vault.create(profileInput("disabled"));
      vault.setEnabled(disabledId, false);
      expect(() => vault.decryptForUse(disabledId)).toThrow(/unavailable/);
      const deletedId = vault.create(profileInput("deleted"));
      vault.delete(deletedId);
      expect(() => vault.decryptForUse(deletedId)).toThrow(/unavailable/);
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("enforces credential RBAC and never returns plaintext through APIs or audit events", async () => {
    const dir = tempDir("routecairn-vault-api-");
    try {
      const database = openDatabase(dir);
      const manager = new ServerSessionManager(database, runtime(keyA));
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      await manager.createUser({ login: "viewer@example.com", password: "viewer password value", role: "VIEWER" });
      database.close();
      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: runtime(keyA).sessionSecret, trustProxy: true, masterKey: keyA, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const created = await apiMutation<any>(handle.url, "/api/credential-profiles", owner, profileInput());
        expect(created.profileId).toMatch(/[0-9a-f-]{36}/);
        const listed = await apiGet<any>(handle.url, "/api/credential-profiles", owner.cookie);
        expect(JSON.stringify(listed)).not.toContain(secretValue);
        const detail = await apiGet<any>(handle.url, `/api/credential-profiles/${created.profileId}`, owner.cookie);
        expect(detail.healthTimeline).toContainEqual(expect.objectContaining({ classification: "UNVERIFIED", reasonCode: "CREDENTIAL_NOT_YET_TESTED" }));
        const renewed = await apiMutation<any>(handle.url, `/api/credential-profiles/${created.profileId}/renew`, owner, {
          secret: { authorizationHeader: "Bearer renewed-secret" },
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          impactDigest: detail.dependencies.impactDigest
        });
        expect(renewed.profile).toMatchObject({ secretVersion: 2, health: { classification: "UNVERIFIED", reasonCode: "RENEWED_RETEST_REQUIRED" } });
        expect(JSON.stringify(renewed)).not.toContain("renewed-secret");
        const audit = await apiGet<any>(handle.url, "/api/audit-events", owner.cookie);
        expect(JSON.stringify(audit)).not.toContain(secretValue);
        expect(JSON.stringify(audit)).not.toContain("renewed-secret");
        const viewer = await login(handle.url, "viewer@example.com", "viewer password value");
        const denied = await fetch(`${handle.url}/api/credential-profiles`, { headers: { cookie: viewer.cookie } });
        expect(denied.status).toBe(403);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("binds saved credential profiles to dashboard scans without persisting plaintext", async () => {
    const dir = tempDir("routecairn-vault-scan-binding-");
    const fixture = await startAuthorizedFixture(secretValue);
    try {
      writeScopeFile(dir, fixture.url);
      const database = openDatabase(dir);
      const manager = new ServerSessionManager(database, runtime(keyA));
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const profileId = vault.create(profileInput("scan account"));
      database.close();

      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: runtime(keyA).sessionSecret, trustProxy: true, masterKey: keyA, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const preview = await apiMutation<any>(handle.url, "/api/scans/plan-preview", owner, {
          target: fixture.url,
          scopeFile: resolve(dir, "scope.json"),
          profile: "authenticated",
          credentialProfileId: profileId
        });
        expect(preview.profile).toBe("authenticated");
        const queued = await apiMutation<any>(handle.url, "/api/scans", owner, {
          target: fixture.url,
          scopeFile: resolve(dir, "scope.json"),
          profile: "authenticated",
          credentialProfileId: profileId,
          authorizationDeclaration: "OWNED: local credential-binding fixture"
        });
        await waitForScan(handle.url, owner.cookie, queued.scanId);
      } finally {
        await handle.close();
      }

      const inspected = openDatabase(dir);
      try {
        const tables = ["scans", "scan_events", "scan_job_leases", "scan_plan_snapshots", "audit_events"];
        for (const table of tables) {
          const rows = inspected.db.prepare(`SELECT * FROM ${table}`).all();
          expect(JSON.stringify(rows)).not.toContain(secretValue);
          expect(JSON.stringify(rows)).not.toContain("cookie-secret");
        }
        const scan = inspected.db.prepare("SELECT safe_configuration_summary FROM scans LIMIT 1").get() as { safe_configuration_summary: string };
        expect(scan.safe_configuration_summary).toContain(profileId);
        expect(scan.safe_configuration_summary).not.toContain(secretValue);
      } finally {
        inspected.close();
      }
    } finally {
      await fixture.close();
      cleanup(dir);
    }
  });

  it("previews two saved credential profiles as an authenticated account pair", async () => {
    const dir = tempDir("routecairn-vault-account-pair-preview-");
    try {
      writeScopeFile(dir, "http://127.0.0.1:9");
      const database = openDatabase(dir);
      const manager = new ServerSessionManager(database, runtime(keyA));
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const accountA = vault.create(profileInput("account A"));
      const accountB = vault.create({ ...profileInput("account B"), safeAlias: "account B safe alias", safeIdentitySummary: { principalId: "principal-b", role: "viewer" } });
      database.close();
      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: runtime(keyA).sessionSecret, trustProxy: true, masterKey: keyA, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const preview = await apiMutation<any>(handle.url, "/api/scans/plan-preview", owner, {
          target: "http://127.0.0.1:9",
          scopeFile: resolve(dir, "scope.json"),
          profile: "authenticated",
          credentialProfileAId: accountA,
          credentialProfileBId: accountB
        });
        expect(preview.profile).toBe("authenticated");
        expect(JSON.stringify(preview)).not.toContain(secretValue);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("rejects an explicit saved account-pair scan when one account credential is missing", async () => {
    const dir = tempDir("routecairn-vault-account-pair-missing-");
    try {
      writeScopeFile(dir, "http://127.0.0.1:9");
      const database = openDatabase(dir);
      const manager = new ServerSessionManager(database, runtime(keyA));
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const accountA = vault.create(profileInput("account A"));
      database.close();
      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: runtime(keyA).sessionSecret, trustProxy: true, masterKey: keyA, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const denied = await fetch(`${handle.url}/api/scans/plan-preview`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": owner.csrf, cookie: owner.cookie, origin: "https://routecairn.example.com" },
          body: JSON.stringify({ target: "http://127.0.0.1:9", scopeFile: resolve(dir, "scope.json"), profile: "authenticated", credentialProfileAId: accountA })
        });
        expect(denied.status).toBe(400);
        const error = await denied.json() as { code: string; diagnostics: Array<{ path: string[]; message: string }> };
        expect(error.code).toBe("REQUEST_VALIDATION_FAILED");
        expect(error.diagnostics).toContainEqual(expect.objectContaining({
          path: ["credentialProfileAId"],
          message: expect.stringContaining("require both Account A and Account B")
        }));
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("rejects unavailable saved credential profiles before launching a scan", async () => {
    const dir = tempDir("routecairn-vault-disabled-launch-");
    try {
      writeScopeFile(dir, "http://127.0.0.1:9");
      const database = openDatabase(dir);
      const manager = new ServerSessionManager(database, runtime(keyA));
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      const vault = new CredentialVault(database, parseVaultKey(keyA, "1"));
      const profileId = vault.create(profileInput("disabled launch"));
      vault.setEnabled(profileId, false);
      database.close();
      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: runtime(keyA).sessionSecret, trustProxy: true, masterKey: keyA, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const denied = await fetch(`${handle.url}/api/scans`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": owner.csrf, cookie: owner.cookie, origin: "https://routecairn.example.com" },
          body: JSON.stringify({ target: "http://127.0.0.1:9", scopeFile: resolve(dir, "scope.json"), profile: "authenticated", credentialProfileId: profileId })
        });
        expect(denied.status).toBe(500);
        expect(await denied.text()).toContain("disabled");
      } finally {
        await handle.close();
      }
      const inspected = openDatabase(dir);
      try {
        expect((inspected.db.prepare("SELECT COUNT(*) AS count FROM scans").get() as { count: number }).count).toBe(0);
      } finally {
        inspected.close();
      }
    } finally {
      cleanup(dir);
    }
  });
});

function profileInput(name = "Account A") {
  return {
    name,
    safeAlias: `${name} safe alias`,
    safeIdentitySummary: { principalAlias: "account-a", role: "analyst" },
    secret: {
      authorizationHeader: secretValue,
      cookies: { sid: "cookie-secret" },
      headers: { "x-tenant-id": "tenant-secret" },
      identityVerification: { endpoint: "https://app.example.com/api/me", principalFieldPath: "id" }
    }
  };
}

function runtime(masterKey: string) {
  return { publicOrigin: "https://routecairn.example.com", sessionSecret: "vault-test-session-secret-with-entropy", trustProxy: true, developmentInsecureHttp: false, masterKey };
}

function openDatabase(dir: string): DashboardDatabase {
  const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath);
  database.migrate();
  return database;
}

function tempDir(prefix: string): string {
  return mkdtempSync(resolve(tmpdir(), prefix));
}

function cleanup(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

async function login(baseUrl: string, loginName: string, password: string): Promise<{ cookie: string; csrf: string }> {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ login: loginName, password })
  });
  if (!response.ok) throw new Error(`Login failed: ${response.status} ${await response.text()}`);
  return {
    cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "",
    csrf: (await response.json() as { csrfToken: string }).csrfToken
  };
}

async function apiGet<T>(baseUrl: string, path: string, cookie: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } });
  if (!response.ok) throw new Error(`GET ${path} failed: ${response.status} ${await response.text()}`);
  return (await response.json()) as T;
}

async function apiMutation<T>(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: "https://routecairn.example.com" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`POST ${path} failed: ${response.status} ${await response.text()}`);
  return (await response.json()) as T;
}

async function waitForScan(baseUrl: string, cookie: string, scanId: string): Promise<void> {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const response = await apiGet<any>(baseUrl, `/api/scans/${scanId}`, cookie);
    if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(response.scan.status)) {
      expect(response.scan.status).toBe("COMPLETED");
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error("Timed out waiting for scan.");
}

function writeScopeFile(dir: string, target: string): void {
  const origin = new URL(target).origin;
  writeFileSync(resolve(dir, "scope.json"), JSON.stringify({
    program: "dashboard credential binding fixture",
    allowedDomains: [new URL(target).hostname],
    disallowedPaths: [],
    allowedMethods: ["GET", "HEAD", "OPTIONS"],
    rateLimitPerSecond: 50,
    concurrency: 1,
    maxDepth: 1,
    sameOriginOnly: true,
    includeSubdomains: false,
    respectRobotsTxt: false,
    userAgent: "RouteCairn-Test/1.0",
    allowedOrigins: [origin]
  }), "utf8");
}

async function startAuthorizedFixture(expectedAuthorization: string): Promise<{ url: string; close(): Promise<void> }> {
  const server = createServer((request, response) => {
    if (request.url === "/robots.txt") {
      response.end("User-agent: *\nAllow: /\n");
      return;
    }
    if (request.headers.authorization !== expectedAuthorization) {
      response.statusCode = 401;
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.end("<!doctype html><title>Unauthorized</title>");
      return;
    }
    response.setHeader("content-type", "text/html; charset=utf-8");
    response.end("<!doctype html><title>Authorized</title><a href='/account'>account</a>");
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture server did not bind.");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
  };
}
