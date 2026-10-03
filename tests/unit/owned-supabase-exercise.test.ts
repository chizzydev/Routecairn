import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exerciseOwnedSupabase, recoverOwnedSupabase, type OwnedSupabaseAuthorization } from "../../src/validation/OwnedSupabaseExercise.js";
import { supabaseRecoverySchema, supabaseResources, type SupabaseAcceptanceStore } from "../../src/validation/SupabaseAcceptanceStore.js";
import { runBoundedHttp } from "../../src/modules/protocolSecurity/ProtocolTransports.js";

vi.mock("../../src/modules/protocolSecurity/ProtocolTransports.js", () => ({ runBoundedHttp: vi.fn() }));
const directories: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); vi.resetAllMocks(); await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });
async function harness(leaks = false, cleanupFails = false) {
  const directory = await mkdtemp(join(tmpdir(), "routecairn-owned-supabase-")); directories.push(directory);
  const accounts = new Map<string, { id: string; email: string; password: string; token: string }>(); let bucket = false; let database = false; let owner: string | undefined; let proof = "";
  const store: SupabaseAcceptanceStore = {
    provision: vi.fn(async (recovery) => { database = true; proof = `proof-${recovery.runId}`; }),
    accounts: vi.fn(async () => [...accounts.values()].map(({ id, email }) => ({ id, email }))),
    objects: vi.fn(async () => owner ? [`${owner}/proof.txt`] : []),
    removeDatabase: vi.fn(async () => { if (cleanupFails) throw new Error("provider-secret-must-not-leak"); database = false; }),
    remaining: vi.fn(async () => accounts.size + Number(bucket) + Number(database))
  };
  vi.spyOn(globalThis, "setTimeout").mockImplementation((callback) => { if (typeof callback === "function") callback(); return 0 as unknown as ReturnType<typeof setTimeout>; });
  const secrets: string[] = [];
  vi.mocked(runBoundedHttp).mockImplementation(async (raw, method, headers, bytes) => {
    const url = new URL(raw); const path = url.pathname; const body = bytes && headers["content-type"] === "application/json" ? JSON.parse(bytes.toString()) : undefined;
    const account = [...accounts.values()].find((item) => `Bearer ${item.token}` === headers.authorization);
    let statusCode = 200; let data: unknown = {};
    if (path === "/auth/v1/admin/users") {
      const value = { id: randomUUID(), email: body.email, password: body.password, token: `token-${randomUUID()}` }; secrets.push(value.password, value.token); accounts.set(value.id, value); data = { id: value.id, email: value.email };
    } else if (path.includes("/auth/v1/admin/users/")) accounts.delete(path.split("/").at(-1)!);
    else if (path === "/auth/v1/token") data = { access_token: [...accounts.values()].find((value) => value.email === body.email)!.token, user: { id: [...accounts.values()].find((value) => value.email === body.email)!.id } };
    else if (path === "/storage/v1/bucket") bucket = true;
    else if (path.startsWith("/storage/v1/bucket/")) { if (method === "DELETE") bucket = false; }
    else if (path.startsWith("/rest/v1/")) {
      const target = body?.target ?? url.searchParams.get("id")?.slice(3);
      if (!account) { statusCode = 401; data = {}; }
      else if (url.searchParams.get("limit") === "0") data = [];
      else if (method === "PATCH") { statusCode = 204; data = undefined; }
      else data = account.id === target || leaks ? [{ id: target, owner_id: target, payload: proof }] : [];
    } else if (path.startsWith("/storage/v1/object/")) {
      if (method === "POST") owner = account?.id;
      else if (method === "DELETE") owner = undefined;
      else if (method === "GET" && account?.id === owner) return { statusCode, headers: {}, body: Buffer.from(proof) };
      else { statusCode = 403; data = { message: "denied" }; }
    } else throw new Error("Unexpected request");
    return { statusCode, headers: {}, body: Buffer.from(data === undefined ? "" : JSON.stringify(data)) };
  });
  const now = Date.now(); const authorization: OwnedSupabaseAuthorization = { schemaVersion: 1, projectRef: "abcdefghijklmnopqrst", authorizedBy: "Fixture owner", authorizationReference: "SYNTHETIC_TEST_ONLY", startsAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600000).toISOString(), maxRequests: 40, rateLimitPerSecond: 2, disposableAccounts: 2, isolatedTableRpcAndStorage: true, deleteCreatedResources: true, cleanupGraceMs: 300000 };
  const credentials = { projectRef: authorization.projectRef, publishableKey: "sb_publishable_fixture", secretKey: "sb_secret_fixture" }; secrets.push(credentials.secretKey);
  return { directory, authorization, credentials, store, secrets, accounts };
}
describe("owned hosted Supabase exercise", () => {
  it("requires real owner success and foreign denial across table, storage and RPC and retains no credentials", async () => {
    const fixture = await harness(); const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("PASSED"); expect(result.evidence.cleanup.status).toBe("VERIFIED"); expect(result.evidence.requestCount).toBe(26); expect(fixture.accounts.size).toBe(0);
    expect(result.evidence.independentAcceptanceVerified).toBe(false); expect(result.evidence.fullEightLaneAcceptance).toBe(false);
    const text = await readFile(join(result.directory, "owned-supabase-exercise.json"), "utf8"); for (const secret of fixture.secrets) expect(text).not.toContain(secret);
    expect(JSON.parse(await readFile(join(result.directory, "private-recovery.json"), "utf8")).stage).toBe("CLEANUP_VERIFIED");
  });
  it("preserves foreign data exposure failures and still removes every created resource", async () => {
    const fixture = await harness(true); const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("FAILED"); expect(result.evidence.cleanup.status).toBe("VERIFIED");
    expect(result.evidence.receipts.filter((value) => value.status === "FAILED").map((value) => value.case)).toEqual(["SUPABASE_TABLE_FOREIGN_DENIED", "SUPABASE_RPC_FOREIGN_DENIED"]);
  });
  it("retains a recoverable cleanup failure without provider exception contents", async () => {
    const fixture = await harness(false, true); const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("FAILED"); expect(result.evidence.cleanup.status).toBe("REQUIRED"); expect(result.evidence.cleanup.failures).toContain("DATABASE_CLEANUP_FAILED"); expect(JSON.stringify(result.evidence)).not.toContain("provider-secret");
  });
  it("records bounded schema-cache propagation without substituting it for owner proof", async () => {
    const fixture = await harness(); const normal = vi.mocked(runBoundedHttp).getMockImplementation()!; let attempts = 0;
    vi.mocked(runBoundedHttp).mockImplementation(async (...args) => {
      if (new URL(args[0]).searchParams.get("limit") === "0" && attempts++ === 0) return { statusCode: 404, headers: {}, body: Buffer.from(JSON.stringify({ code: "PGRST205" })) };
      return normal(...args);
    });
    const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("PASSED"); expect(result.evidence.receipts.filter((receipt) => receipt.status === "PENDING")).toHaveLength(1);
    expect(result.evidence.receipts.find((receipt) => receipt.case === "SUPABASE_TABLE_OWNER_ALLOWED")?.status).toBe("PASSED");
  });
  it("stops an unavailable Data API after three readiness requests and cleans provisioned identities", async () => {
    const fixture = await harness(); const normal = vi.mocked(runBoundedHttp).getMockImplementation()!;
    vi.mocked(runBoundedHttp).mockImplementation(async (...args) => new URL(args[0]).searchParams.get("limit") === "0" ? { statusCode: 404, headers: {}, body: Buffer.from(JSON.stringify({ code: "PGRST205" })) } : normal(...args));
    const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("FAILED"); expect(result.evidence.primaryError).toBe("SUPABASE_SCHEMA_CACHE_NOT_READY"); expect(result.evidence.cleanup.status).toBe("VERIFIED");
    expect(result.evidence.receipts.filter((receipt) => receipt.status === "PENDING")).toHaveLength(3);
    expect(result.evidence.receipts.some((receipt) => receipt.case === "SUPABASE_TABLE_OWNER_ALLOWED")).toBe(false);
  });
  it("recovers a provisioned identity even when the admin response is lost and never retains transport secrets", async () => {
    const fixture = await harness(); const normal = vi.mocked(runBoundedHttp).getMockImplementation()!; let lost = false;
    vi.mocked(runBoundedHttp).mockImplementation(async (...args) => {
      const value = await normal(...args);
      if (!lost && new URL(args[0]).pathname === "/auth/v1/admin/users") { lost = true; throw new Error("secret-provider-exception"); }
      return value;
    });
    const result = await exerciseOwnedSupabase(fixture.authorization, fixture.credentials, fixture.store, fixture.directory);
    expect(result.evidence.status).toBe("FAILED"); expect(result.evidence.cleanup.status).toBe("VERIFIED"); expect(fixture.accounts.size).toBe(0); expect(JSON.stringify(result.evidence)).not.toContain("secret-provider-exception");
  });
  it("rejects mismatched or expired authorization and unrelated recovery resources before transmission", async () => {
    const fixture = await harness(); await expect(exerciseOwnedSupabase(fixture.authorization, { ...fixture.credentials, projectRef: "zzzzzzzzzzzzzzzzzzzz" }, fixture.store, fixture.directory)).rejects.toThrow("MISMATCH");
    const expired = { ...fixture.authorization, expiresAt: new Date(Date.now() - 500).toISOString() };
    await expect(exerciseOwnedSupabase(expired, fixture.credentials, fixture.store, fixture.directory)).rejects.toThrow("INACTIVE");
    const recovery = { schemaVersion: 1 as const, projectRef: "zzzzzzzzzzzzzzzzzzzz", runId: randomUUID(), stage: "PREPARED" as const };
    await expect(recoverOwnedSupabase(recovery, fixture.authorization, fixture.credentials, fixture.store)).rejects.toThrow("MISMATCH");
    expect(supabaseRecoverySchema.safeParse({ ...recovery, runId: "users; DROP TABLE users" }).success).toBe(false); expect(() => supabaseResources({ ...recovery, runId: "users" })).toThrow();
    expect(runBoundedHttp).not.toHaveBeenCalled(); expect(fixture.store.provision).not.toHaveBeenCalled();
  });
});
