import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { HttpRequest, HttpResponse } from "../../src/core/http/HttpTypes.js";
import { ControlledMutationExecutor } from "../../src/core/offensive/ControlledMutationExecutor.js";
import { controlledMutationContractSchema, type MutationTransport } from "../../src/core/offensive/ControlledMutationTypes.js";
import { GlobalMutationLock, MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { MutationJournalRegistry } from "../../src/core/offensive/MutationJournalRegistry.js";
import { readMutationCleanupStatus } from "../../src/core/offensive/MutationCleanupStatus.js";

class StatefulTransport implements MutationTransport {
  public role = "user";
  public requests: HttpRequest[] = [];
  public rejectAttack = false;
  public ignoreRollback = false;
  public delayedReads = 0;
  public beforeAttack?: (() => Promise<void>) | undefined;

  public async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    if (request.method !== "GET") {
      const nextRole = JSON.parse(request.body ?? "{}") as { role?: string };
      if (nextRole.role === "admin") await this.beforeAttack?.();
      if (nextRole.role === "admin" && this.rejectAttack) return response(request, 403, { error: "forbidden" });
      if (!(nextRole.role === "user" && this.ignoreRollback) && nextRole.role) this.role = nextRole.role;
      return response(request, 200, { accepted: true });
    }
    if (this.delayedReads > 0 && this.role === "admin") {
      this.delayedReads -= 1;
      return response(request, 200, { id: "disposable-1", role: "user" });
    }
    return response(request, 200, { id: "disposable-1", role: this.role });
  }
}

describe("Controlled Offensive Execution & Recovery Kernel", () => {
  it("proves a mutation, rolls it back, verifies restoration, and never journals raw bodies", async () => {
    const directory = await tempDirectory();
    const transport = new StatefulTransport();
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory, sleep: async () => undefined }).execute(contract());

    expect(result.securityOutcome).toBe("EXPLOIT_PROVEN");
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(transport.role).toBe("user");
    const journal = await readFile(join(directory, "mutation-journal.json"), "utf8");
    expect(journal).not.toContain('"role":"admin"');
    expect(journal).not.toContain('"role":"user"');
    expect(journal).toContain("requestBodyAttestation");
    expect(await readdir(directory)).not.toContain("case-1.recovery.enc");
  });

  it("durably arms recovery before the mutation request can reach the transport", async () => {
    const directory = await tempDirectory();
    const transport = new StatefulTransport();
    transport.beforeAttack = async () => {
      const entries = await new MutationJournal(join(directory, "mutation-journal.json")).read();
      const armed = entries.at(-1);
      expect(armed?.stage).toBe("MUTATION_ARMED");
      expect(armed?.recoveryBundleRef).toContain("case-1.recovery.enc");
      expect(await readdir(directory)).toContain("case-1.recovery.enc");
    };
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory, sleep: async () => undefined }).execute(contract());
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
  });

  it("does not treat a fake 2xx response as exploit proof", async () => {
    const transport = new StatefulTransport();
    transport.rejectAttack = true;
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: await tempDirectory(), sleep: async () => undefined }).execute(contract());
    expect(result.securityOutcome).toBe("SECURE_FOR_CASE");
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
  });

  it("uses bounded polling to detect delayed authoritative state changes", async () => {
    const transport = new StatefulTransport();
    transport.delayedReads = 1;
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: await tempDirectory(), sleep: async () => undefined }).execute(contract());
    expect(result.securityOutcome).toBe("EXPLOIT_PROVEN");
    expect(result.notes).toContain("Verification matched on attempt 2.");
  });

  it("blocks expired authorization and unavailable deletion without sending requests", async () => {
    const transport = new StatefulTransport();
    const expired = contract({ expiresAt: "2020-01-01T00:00:00.000Z" });
    const expiredResult = await new ControlledMutationExecutor(transport, { journalDirectory: await tempDirectory() }).execute(expired);
    expect(expiredResult.outcome).toBe("BLOCKED_BY_SAFETY");
    expect(transport.requests).toHaveLength(0);

    const deletion = controlledMutationContractSchema.parse({ ...rawContract(), attack: { ...rawContract().attack, request: { ...rawContract().attack.request, method: "DELETE" }, semanticEffect: "DELETE" } });
    const deletionResult = await new ControlledMutationExecutor(transport, { journalDirectory: await tempDirectory() }).execute(deletion);
    expect(deletionResult.outcome).toBe("BLOCKED_BY_SAFETY");
    expect(transport.requests).toHaveLength(0);
  });

  it("keeps encrypted recovery material and raises CLEANUP_FAILED when restoration cannot be proven", async () => {
    const directory = await tempDirectory();
    const transport = new StatefulTransport();
    transport.ignoreRollback = true;
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory, sleep: async () => undefined }).execute(contract());
    expect(result.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(await readdir(directory)).toContain("case-1.recovery.enc");
    expect((await readFile(join(directory, "case-1.recovery.enc"), "utf8"))).not.toContain('"role":"user"');
    const sentBeforeRetry = transport.requests.length;
    const blocked = await new ControlledMutationExecutor(transport, { journalDirectory: directory }).execute(contract());
    expect(blocked.outcome).toBe("BLOCKED_BY_SAFETY");
    expect(transport.requests).toHaveLength(sentBeforeRetry);
  });

  it("recovers an unfinished mutation after restart from the encrypted rollback bundle", async () => {
    const directory = await tempDirectory();
    const bundlePath = await new MutationRecoveryVault(directory).seal({
      caseId: "recovery-1",
      targetOrigin: "https://example.test",
      rollbackRequest: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: '{"role":"user"}' },
      rollbackVerification: { request: { url: "https://example.test/api/users/disposable-1", method: "GET" }, matchPreStateHash: true, attempts: 1, delayMs: 0 },
      preStateHash: hash({ id: "disposable-1", role: "user" })
    });
    const transport = new StatefulTransport();
    transport.role = "admin";
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundlePath, "recovery-1");
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(transport.role).toBe("user");
    expect(await readdir(directory)).not.toContain("recovery-1.recovery.enc");
  });

  it("excludes concurrent mutations with a global lock and exposes unresolved journal cases", async () => {
    const directory = await tempDirectory();
    const first = new GlobalMutationLock(join(directory, "global.lock"));
    const second = new GlobalMutationLock(join(directory, "global.lock"));
    await first.acquire("one");
    await expect(second.acquire("two")).rejects.toThrow("global lock");
    await first.release();
    const journal = new MutationJournal(join(directory, "journal.json"));
    await journal.append({ caseId: "unfinished", stage: "MUTATION_SENT", mode: "CONTROLLED_MUTATION", targetOrigin: "https://example.test", targetIdentityFingerprint: "fingerprint" });
    expect(await journal.unresolvedCaseIds()).toEqual(["unfinished"]);
  });

  it("reclaims a crash-orphaned lock so restart recovery can proceed", async () => {
    const directory = await tempDirectory();
    const path = join(directory, "global.lock");
    await writeFile(path, JSON.stringify({ caseId: "crashed", pid: 2_147_483_647, acquiredAt: "2020-01-01T00:00:00.000Z" }));
    const lock = new GlobalMutationLock(path);
    await expect(lock.acquire("recovery")).resolves.toBeUndefined();
    await lock.release();
  });

  it("discovers an orphaned encrypted recovery bundle across a registered custom journal directory", async () => {
    const dashboardDirectory = await tempDirectory();
    const customDirectory = await tempDirectory();
    const registryPath = join(dashboardDirectory, "controlled-mutation-journals.json");
    await new MutationJournalRegistry(registryPath).register(customDirectory);
    await new MutationRecoveryVault(customDirectory).seal({
      caseId: "orphaned-case",
      targetOrigin: "https://example.test",
      rollbackRequest: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: '{"role":"user"}' },
      rollbackVerification: { request: { url: "https://example.test/api/users/disposable-1", method: "GET" }, matchPreStateHash: true, attempts: 1, delayMs: 0 },
      preStateHash: hash({ id: "disposable-1", role: "user" })
    });

    const status = await readMutationCleanupStatus(join(dashboardDirectory, "controlled-mutations"), registryPath);
    expect(status.cleanupRequired).toBe(1);
    expect(status.globalMutationActive).toBe(true);
    expect(status.cases[0]).toMatchObject({ caseId: "orphaned-case", stage: "MUTATION_STATE_UNCERTAIN", recoveryBundleAvailable: true, operatorActionRequired: true });
    expect(JSON.stringify(status)).not.toContain(customDirectory);
    expect(JSON.stringify(status)).not.toContain('"role":"user"');
  });
});

function contract(authorization?: { expiresAt: string }) {
  const raw = rawContract();
  if (authorization) raw.authorization.expiresAt = authorization.expiresAt;
  return controlledMutationContractSchema.parse(raw);
}

function rawContract() {
  return {
    schemaVersion: 1,
    caseId: "case-1",
    targetOrigin: "https://example.test",
    mode: "CONTROLLED_MUTATION",
    environment: "STAGING",
    productionAcknowledged: false,
    authorization: { authorizedBy: "security-owner", changeTicket: "SEC-42", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
    target: { disposable: true, type: "user", alias: "disposable-user", identityFingerprint: hash("disposable-1"), identityAssertion: { path: "id", operator: "EQUALS", expectedValue: "disposable-1" } },
    attack: { request: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: '{"role":"admin"}' }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" },
    precondition: { request: { url: "https://example.test/api/users/disposable-1", method: "GET" }, assertions: [{ path: "id", operator: "EQUALS", expectedValue: "disposable-1" }, { path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 },
    impact: { request: { url: "https://example.test/api/users/disposable-1", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }], attempts: 3, delayMs: 0 },
    rollback: { request: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: '{"role":"user"}' }, verification: { request: { url: "https://example.test/api/users/disposable-1", method: "GET" }, matchPreStateHash: true, attempts: 2, delayMs: 0 } }
  };
}

function response(request: HttpRequest, statusCode: number, body: unknown): HttpResponse {
  const serialized = JSON.stringify(body);
  return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode, headers: { "content-type": "application/json" }, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: hash(body), responseTimeMs: 1, redirectChain: [] };
}

function hash(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
async function tempDirectory(): Promise<string> { return mkdtemp(join(tmpdir(), "routecairn-mutation-")); }
