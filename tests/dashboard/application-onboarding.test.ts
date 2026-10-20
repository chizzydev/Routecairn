import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { ApplicationOnboardingService } from "../../src/dashboard/execution/ApplicationOnboardingService.js";
export const onboardingInput = () => ({
  displayName: "Owned local app",
  origin: "http://127.0.0.1:9000",
  authorizationSummary: "Owner authorizes only reviewed safe GET observations",
  identityPath: "/identity",
  principalField: "principal",
  tenantField: "tenant",
  roleField: "role",
  seedPath: "/ledger/start",
  objectField: "id",
  objectTenantField: "tenant",
  actors: Object.fromEntries(
    ["primary", "account_a", "account_b"].map((slot) => [
      slot,
      {
        principal: slot,
        tenant: slot === "account_b" ? "south" : "north",
        role: slot,
        authorizationHeader: "Bearer synthetic-" + slot,
        expiresAt: "2099-01-01T00:00:00Z"
      }
    ])
  ),
  ownedReadOnlyConfirmed: true
});
it("atomically encrypts new target actors without dispatch and survives native SQLite restart", () => {
  const root = createOwnedTestDirectory("onboard-native-restart"),
    p = join(root, "owned.db");
  let db = new DashboardDatabase(p);
  db.migrate();
  try {
    const org = new OrganizationService(db).defaultOrganizationId(),
      vault = new CredentialVault(db, { bytes: Buffer.alloc(32, 91), version: "1" }),
      s = new ApplicationOnboardingService(db, vault),
      r = s.create(org, onboardingInput(), "owner");
    expect(r.requestsSent).toBe(0);
    expect(r.identityStatus).toBe("DECLARED_NOT_VERIFIED");
    expect(JSON.stringify(r)).not.toContain("Bearer");
    const rows = db.db.prepare("SELECT ciphertext FROM credential_profiles").all();
    expect(JSON.stringify(rows)).not.toContain("synthetic");
    db.close();
    db = new DashboardDatabase(p);
    db.migrate();
    expect(db.db.prepare("SELECT count(*) n FROM targets").get()).toEqual({ n: 1 });
    expect(db.db.prepare("SELECT count(*) n FROM credential_profiles").get()).toEqual({ n: 3 });
    expect(db.db.prepare("SELECT count(*) n FROM scans").get()).toEqual({ n: 0 });
    writeFileSync(
      join(root, "NATIVE_SQLITE_RECEIPT.json"),
      JSON.stringify({
        result: r,
        integrity: db.db.pragma("integrity_check"),
        foreignKeys: db.db.pragma("foreign_key_check"),
        rows,
        scans: 0,
        restart: true
      }),
      { flag: "wx" }
    );
  } finally {
    db.close();
    retainOwnedTestDirectory(root);
  }
});
it("rolls back all declarations on interrupted credential persistence with no partial target adoption", () => {
  const root = createOwnedTestDirectory("onboard-rollback"),
    db = new DashboardDatabase(join(root, "owned.db"));
  db.migrate();
  try {
    const org = new OrganizationService(db).defaultOrganizationId(),
      s = new ApplicationOnboardingService(db, new CredentialVault(db, { bytes: Buffer.alloc(32, 92), version: "1" }));
    db.db.exec(
      "CREATE TRIGGER inject_fixture_failure BEFORE INSERT ON credential_profiles WHEN (SELECT COUNT(*) FROM credential_profiles)>0 BEGIN SELECT RAISE(ABORT,'OWNED_FAULT_AFTER_FIRST_CREDENTIAL'); END"
    );
    expect(() => s.create(org, onboardingInput(), "owner")).toThrow("OWNED_FAULT");
    const counts = {
      targets: db.db.prepare("SELECT count(*) n FROM targets").get(),
      credentials: db.db.prepare("SELECT count(*) n FROM credential_profiles").get(),
      integrity: db.db.pragma("integrity_check")
    };
    expect(counts.targets).toEqual({ n: 0 });
    expect(counts.credentials).toEqual({ n: 0 });
    writeFileSync(join(root, "ROLLBACK_RECEIPT.json"), JSON.stringify(counts), { flag: "wx" });
  } finally {
    db.close();
    retainOwnedTestDirectory(root);
  }
});
it("rejects off-origin, unsafe paths, expired credentials, duplicate principals and missing authority declarations", () => {
  const root = createOwnedTestDirectory("onboard-refusals"),
    db = new DashboardDatabase(join(root, "owned.db"));
  db.migrate();
  try {
    const org = new OrganizationService(db).defaultOrganizationId(),
      s = new ApplicationOnboardingService(db, new CredentialVault(db, { bytes: Buffer.alloc(32, 93), version: "1" }));
    for (const v of [
      { ...onboardingInput(), origin: "https://outside.invalid" },
      { ...onboardingInput(), seedPath: "/delete" },
      { ...onboardingInput(), seedPath: "/a/../b" },
      { ...onboardingInput(), ownedReadOnlyConfirmed: false },
      { ...onboardingInput(), actors: { ...onboardingInput().actors, account_a: onboardingInput().actors.primary } }
    ])
      expect(() => s.create(org, v, "owner")).toThrow();
    expect(db.db.prepare("SELECT count(*) n FROM targets").get()).toEqual({ n: 0 });
  } finally {
    db.close();
    retainOwnedTestDirectory(root);
  }
});
