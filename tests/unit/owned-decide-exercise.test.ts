import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exerciseOwnedDecide, type DisposableDecideAccount, type OwnedDecideAccountStore } from "../../src/validation/OwnedDecideExercise.js";
import { decideRecoverySchema } from "../../src/validation/DecideAcceptanceAccounts.js";
import { runBoundedHttp } from "../../src/modules/protocolSecurity/ProtocolTransports.js";

vi.mock("../../src/modules/protocolSecurity/ProtocolTransports.js", () => ({ runBoundedHttp: vi.fn() }));
const directories: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); vi.resetAllMocks(); await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

async function harness(rotates = true) {
  const directory = await mkdtemp(join(tmpdir(), "routecairn-owned-decide-test-")); directories.push(directory);
  const accounts = new Map<string, DisposableDecideAccount>(); const access = new Map<string, string>(); const refresh = new Map<string, string>(); const sessionIds = new Map<string, string>();
  const issuedPasswords: string[] = [];
  const store: OwnedDecideAccountStore = {
    provision: vi.fn(async (created) => { for (const account of created) { accounts.set(account.id, { ...account }); sessionIds.set(account.id, randomUUID()); issuedPasswords.push(account.password); } }),
    remove: vi.fn(async (created) => { for (const account of created) accounts.delete(account.id); }),
    remaining: vi.fn(async () => ({ users: accounts.size, sessions: 0 }))
  };
  vi.mocked(runBoundedHttp).mockImplementation(async (raw, method, headers, bytes) => {
    const path = new URL(raw).pathname; const body = bytes ? JSON.parse(bytes.toString()) : undefined;
    const bearer = headers.authorization?.replace(/^Bearer /, ""); const id = bearer ? access.get(bearer) : undefined;
    const account = id ? accounts.get(id) : undefined;
    let statusCode = 200; let data: unknown;
    const publicUser = (value: DisposableDecideAccount) => ({ id: value.id, display_name: value.displayName });
    if (path.endsWith("/login")) {
      const user = [...accounts.values()].find((item) => item.email === body.email && item.password === body.password);
      if (!user) statusCode = 401;
      else { const a = `access-${randomUUID()}`; const r = `refresh-${randomUUID()}`; access.set(a, user.id); refresh.set(r, user.id); data = { user: publicUser(user), access_token: a, refresh_token: r }; }
    } else if (path.endsWith("/refresh")) {
      const userId = refresh.get(body.refresh_token); const user = userId ? accounts.get(userId) : undefined;
      if (!user) statusCode = 401;
      else { const a = `access-${randomUUID()}`; const r = rotates ? `refresh-${randomUUID()}` : body.refresh_token; if (rotates) refresh.delete(body.refresh_token); refresh.set(r, user.id); access.set(a, user.id); data = { user: publicUser(user), access_token: a, refresh_token: r }; }
    } else if (path.endsWith("/logout")) {
      const userId = refresh.get(body.refresh_token); refresh.delete(body.refresh_token);
      for (const [key, value] of access) if (value === userId) access.delete(key);
    } else if (!account) statusCode = 401;
    else if (path.endsWith("/me")) data = publicUser(account);
    else if (path.endsWith("/sessions")) data = [{ id: sessionIds.get(account.id) }];
    else if (path.includes("/sessions/") && method === "DELETE") statusCode = 404;
    else if (path.endsWith("/profile")) { account.displayName = body.display_name; data = publicUser(account); }
    else if (path.endsWith("/account") && method === "DELETE") accounts.delete(account.id);
    else statusCode = 404;
    return { statusCode, headers: {}, body: Buffer.from(JSON.stringify({ data })) };
  });
  const now = Date.now();
  const authorization = { schemaVersion: 1 as const, product: "Decide" as const, apiOrigin: "https://owned-api.decide.com.ng", authorizedBy: "Fixture owner", authorizationReference: "SYNTHETIC_TEST_ONLY", startsAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600000).toISOString(), maxRequests: 40, rateLimitPerSecond: 2, disposableAccounts: 2 as const, administrativeProvisioning: true as const, sessionLifecycle: true as const, ownAccountProfileChanges: true as const, crossAccountSessionDenial: true as const, deleteCreatedAccounts: true as const, cleanupGraceMs: 300000 };
  return { directory, authorization, store, accounts, issuedPasswords };
}

describe("owned Decide disposable exercise", () => {
  it("provisions fresh accounts, verifies ownership/lifecycle contracts and removes credentials from evidence", async () => {
    const h = await harness(); const { evidence, directory } = await exerciseOwnedDecide(h.authorization, h.store, h.directory);
    expect(evidence).toMatchObject({ status: "PASSED", cleanup: "VERIFIED", fullEightLaneAcceptance: false, independentAcceptanceVerified: false, requestCount: 20 });
    expect(h.store.provision).toHaveBeenCalledOnce(); expect(h.store.remove).toHaveBeenCalledOnce(); expect(h.accounts.size).toBe(0);
    const report = await readFile(join(directory, "owned-decide-exercise.json"), "utf8"); const recovery = await readFile(join(directory, "private-recovery.json"), "utf8");
    for (const secret of h.issuedPasswords) { expect(report).not.toContain(secret); expect(recovery).not.toContain(secret); }
    expect(report).not.toContain("@acceptance.decide.invalid"); expect(report).not.toContain("access_token");
    expect(decideRecoverySchema.parse(JSON.parse(recovery)).stage).toBe("CLEANUP_VERIFIED");
  }, 30000);

  it("retains a nonrotating refresh token as failed evidence while still cleaning up", async () => {
    const h = await harness(false); const { evidence } = await exerciseOwnedDecide(h.authorization, h.store, h.directory);
    expect(evidence.status).toBe("FAILED"); expect(evidence.cleanup).toBe("VERIFIED");
    expect(evidence.receipts.filter((receipt) => receipt.status === "FAILED").map((receipt) => receipt.case)).toEqual(["REFRESH_TOKEN_ROTATES", "OLD_REFRESH_REPLAY_DENIED"]);
  }, 30000);

  it("cleans exact provisioned identities after a transport error without retaining its secret-bearing message", async () => {
    const h = await harness(); vi.mocked(runBoundedHttp).mockRejectedValue(new Error("leaked-password-should-not-be-retained"));
    const { evidence } = await exerciseOwnedDecide(h.authorization, h.store, h.directory);
    expect(evidence).toMatchObject({ status: "FAILED", primaryError: "OWNED_DECIDE_TRANSPORT_FAILED", cleanup: "VERIFIED" });
    expect(h.store.remove).toHaveBeenCalledOnce(); expect(JSON.stringify(evidence)).not.toContain("leaked-password");
  });

  it("refuses expired authorization before provisioning and refuses unrelated recovery identities", async () => {
    const h = await harness();
    await expect(exerciseOwnedDecide({ ...h.authorization, startsAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-01-02T00:00:00.000Z" }, h.store, h.directory)).rejects.toThrow("AUTHORIZATION_INACTIVE");
    expect(h.store.provision).not.toHaveBeenCalled(); expect(runBoundedHttp).not.toHaveBeenCalled();
    expect(() => decideRecoverySchema.parse({ schemaVersion: 1, runId: randomUUID(), apiOrigin: h.authorization.apiOrigin, stage: "PROVISIONED", accounts: [{ id: randomUUID(), email: "owner@decide.com.ng" }, { id: randomUUID(), email: "someone@decide.com.ng" }] })).toThrow();
  });
});
