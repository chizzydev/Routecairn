import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ProjectRepository, SavedConfigurationRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { CredentialVault, parseVaultKey } from "../../src/dashboard/credentials/CredentialVault.js";

function fixture() {
  const dir = mkdtempSync(resolve(tmpdir(), "routecairn-admin-parity-"));
  const database = new DashboardDatabase(resolve(dir, "dashboard.sqlite")); database.migrate();
  return { dir, database, close: () => { database.close(); rmSync(dir, { recursive: true, force: true }); } };
}

describe("administration parity repositories", () => {
  it("archives/restores projects and enforces optimistic concurrency", () => {
    const item = fixture(); try {
      const projects = new ProjectRepository(item.database);
      const id = projects.create({ name: "Alpha", tags: ["client"], defaultScope: {} });
      const current = projects.get(id)!;
      projects.update(id, { name: "Alpha renamed", tags: ["client"], defaultScope: {}, expectedVersion: current.rowVersion });
      expect(() => projects.update(id, { name: "stale", tags: [], defaultScope: {}, expectedVersion: current.rowVersion })).toThrow(/CONFLICT/);
      projects.archive(id); expect(projects.get(id)).toBeUndefined(); expect(projects.list(undefined, true)[0]?.archived).toBe(true);
      projects.restore(id); expect(projects.get(id)?.name).toBe("Alpha renamed");
    } finally { item.close(); }
  });

  it("keeps target origin immutable while editing safe metadata", () => {
    const item = fixture(); try {
      const targets = new TargetRepository(item.database);
      const id = targets.create({ displayName: "Portal", baseOrigin: "https://portal.example.test/path", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned controlled production target", approvedScope: {} });
      const current = targets.get(id)!;
      targets.update(id, { displayName: "Portal renamed", description: "Safe note", tags: ["prod"], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned controlled production target", approvedScope: {}, defaultAuthTemplate: {}, expectedVersion: current.rowVersion });
      expect(targets.get(id)?.baseOrigin).toBe("https://portal.example.test");
    } finally { item.close(); }
  });

  it("creates immutable configuration versions, diffs, clones, and restores", () => {
    const item = fixture(); try {
      const configs = new SavedConfigurationRepository(item.database);
      const base = { name: "Baseline", profile: "quick", modules: ["header-review"], limits: {}, scopeSettings: {}, browserPolicySettings: {}, evidenceLevel: "normal", workflowRefs: {} };
      const id = configs.create(base); const current = configs.get(id)!;
      expect(configs.update(id, { ...base, profile: "full", expectedVersion: Number(current.rowVersion), changeSummary: "Increase coverage" })).toBe(2);
      const diff = configs.diff(id, 1, 2).changes as Array<{ field: string }>;
      expect(diff.map((change) => change.field)).toEqual(["profile"]);
      expect(configs.history(id)).toHaveLength(2);
      expect(configs.get(configs.clone(id, "Baseline copy"))?.name).toBe("Baseline copy");
      configs.archive(id); expect(configs.get(id)).toBeUndefined(); configs.restore(id); expect(configs.get(id)?.currentVersion).toBe(2);
    } finally { item.close(); }
  });

  it("refuses to disable or demote the final enabled owner", async () => {
    const item = fixture(); try {
      const sessions = new ServerSessionManager(item.database, { publicOrigin: "https://routecairn.test", sessionSecret: "x".repeat(48), trustProxy: true, developmentInsecureHttp: false });
      const owner = await sessions.createFirstOwner("owner@example.test", "correct horse battery staple");
      expect(() => sessions.setEnabled(owner, false)).toThrow(/FINAL_OWNER_REQUIRED/);
      expect(() => sessions.setRole(owner, "ANALYST")).toThrow(/FINAL_OWNER_REQUIRED/);
      await sessions.createUser({ login: "owner2@example.test", password: "second correct horse battery", role: "OWNER" });
      expect(() => sessions.setRole(owner, "ANALYST")).not.toThrow();
    } finally { item.close(); }
  });

  it("separates credential metadata edits, secret replacement, and dependency-aware deletion", () => {
    const item = fixture(); try {
      const vault = new CredentialVault(item.database, parseVaultKey(Buffer.from("k".repeat(32)).toString("base64url"), "qa"));
      const id = vault.create({ name: "Account", safeAlias: "account-a", safeIdentitySummary: { role: "analyst" }, secret: { authorizationHeader: "Bearer original" } });
      const before = item.database.db.prepare("SELECT ciphertext FROM credential_profiles WHERE id = ?").get(id) as { ciphertext: string };
      vault.updateMetadata(id, { name: "Renamed", description: "Safe metadata", safeAlias: "account-a", safeIdentitySummary: { role: "analyst" } });
      const afterMetadata = item.database.db.prepare("SELECT ciphertext FROM credential_profiles WHERE id = ?").get(id) as { ciphertext: string };
      expect(afterMetadata.ciphertext).toBe(before.ciphertext);
      vault.replaceSecret(id, { authorizationHeader: "Bearer replacement" });
      const afterSecret = item.database.db.prepare("SELECT ciphertext FROM credential_profiles WHERE id = ?").get(id) as { ciphertext: string };
      expect(afterSecret.ciphertext).not.toBe(before.ciphertext); expect(vault.decryptForUse(id).authorizationHeader).toBe("Bearer replacement");
      const targets = new TargetRepository(item.database);
      targets.create({ displayName: "Bound", baseOrigin: "https://bound.example.test", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned credential-bound test target", approvedScope: {}, defaultCredentialProfileId: id });
      expect(vault.dependencies(id).canDelete).toBe(false); expect(() => vault.delete(id)).toThrow(/CREDENTIAL_IN_USE/);
    } finally { item.close(); }
  });
});
