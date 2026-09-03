import { createHash } from "node:crypto";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ControlledMutationExecutor } from "../../src/core/offensive/ControlledMutationExecutor.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import type { HttpRequest, HttpResponse } from "../../src/core/http/HttpTypes.js";
import type { MutationTransport } from "../../src/core/offensive/ControlledMutationTypes.js";

describe("controlled mutation recovery binding", () => {
  it("refuses a recovery bundle when the caller case differs from the encrypted case", async () => {
    const directory = await tempDirectory();
    const bundle = await new MutationRecoveryVault(directory).seal({
      caseId: "case-a",
      targetOrigin: "https://example.test",
      targetIdentityFingerprint: "a".repeat(64),
      authorizationExpiresAt: "2099-01-01T00:00:00.000Z",
      contractDigest: "b".repeat(64),
      rollbackRequest: request("PATCH", "{\"role\":\"user\"}"),
      rollbackVerification: { request: request("GET"), assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 }
    });
    const transport = new CountingTransport();
    await expect(new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundle, "case-b")).rejects.toThrow();
    expect(transport.requests).toHaveLength(0);
  });

  it("refuses an expired recovery authorization before sending rollback", async () => {
    const directory = await tempDirectory();
    const vault = new MutationRecoveryVault(directory);
    const bundle = await vault.seal({
      caseId: "expired-case", targetOrigin: "https://example.test", targetIdentityFingerprint: "a".repeat(64), authorizationExpiresAt: "2020-01-01T00:00:00.000Z", contractDigest: "b".repeat(64),
      rollbackRequest: request("PATCH", "{\"role\":\"user\"}"), rollbackVerification: { request: request("GET"), assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 }
    });
    const transport = new CountingTransport();
    await expect(new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundle, "expired-case")).rejects.toThrow(/expired/i);
    expect(transport.requests).toHaveLength(0);
  });

  it("stores recovery binding metadata without exposing request bodies", async () => {
    const directory = await tempDirectory();
    const transport = new CountingTransport();
    const contract = validContract();
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory, sleep: async () => undefined }).execute(contract);
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(await readdir(directory)).not.toContain("binding-case.recovery.enc");
  });

  it("re-verifies the bound actor and disposable object before restart recovery", async () => {
    const directory = await tempDirectory();
    const actorAssertion = { path: "actor.id", operator: "EQUALS" as const, expectedValue: "actor-1" };
    const targetAssertion = { path: "object.id", operator: "EQUALS" as const, expectedValue: "target-1" };
    const bundle = await new MutationRecoveryVault(directory).seal({
      caseId: "bound-recovery", targetOrigin: "https://example.test", targetIdentityFingerprint: hash("target-1"), authorizationExpiresAt: "2099-01-01T00:00:00.000Z", contractDigest: "b".repeat(64),
      actorBinding: { credentialReferenceFingerprint: "c".repeat(64), identityFingerprint: hash("actor-1"), identityAssertion: actorAssertion },
      actorIdentityVerification: { request: { url: "https://example.test/api/session/me", method: "GET" as const }, assertions: [actorAssertion], attempts: 1, delayMs: 0 },
      targetIdentityVerification: { request: { url: "https://example.test/api/target-1", method: "GET" as const }, assertions: [targetAssertion], attempts: 1, delayMs: 0 },
      rollbackRequest: request("PATCH", "{\"role\":\"user\"}"), rollbackVerification: { request: request("GET"), assertions: [{ path: "state.role", operator: "EQUALS" as const, expectedValue: "user" }], attempts: 1, delayMs: 0 }
    });
    const transport = new BindingRecoveryTransport();
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundle, "bound-recovery");
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(transport.requests.map((item) => `${item.method} ${new URL(item.url).pathname}`)).toEqual(["GET /api/session/me", "GET /api/target-1", "PATCH /api/target-1", "GET /api/target-1"]);
  });

  it("preserves recovery and sends no rollback when the actor binding changes", async () => {
    const directory = await tempDirectory();
    const actorAssertion = { path: "actor.id", operator: "EQUALS" as const, expectedValue: "actor-1" };
    const targetAssertion = { path: "object.id", operator: "EQUALS" as const, expectedValue: "target-1" };
    const bundle = await new MutationRecoveryVault(directory).seal({
      caseId: "mismatched-actor", targetOrigin: "https://example.test", targetIdentityFingerprint: hash("target-1"), authorizationExpiresAt: "2099-01-01T00:00:00.000Z", contractDigest: "b".repeat(64),
      actorBinding: { credentialReferenceFingerprint: "c".repeat(64), identityFingerprint: hash("actor-1"), identityAssertion: actorAssertion },
      actorIdentityVerification: { request: { url: "https://example.test/api/session/me", method: "GET" as const }, assertions: [actorAssertion], attempts: 1, delayMs: 0 },
      targetIdentityVerification: { request: { url: "https://example.test/api/target-1", method: "GET" as const }, assertions: [targetAssertion], attempts: 1, delayMs: 0 },
      rollbackRequest: request("PATCH", "{\"role\":\"user\"}"), rollbackVerification: { request: request("GET"), assertions: [{ path: "state.role", operator: "EQUALS" as const, expectedValue: "user" }], attempts: 1, delayMs: 0 }
    });
    const transport = new BindingRecoveryTransport("actor-2");
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundle, "mismatched-actor");
    expect(result.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(transport.requests.map((item) => item.method)).toEqual(["GET"]);
    expect(await readdir(directory)).toContain("mismatched-actor.recovery.enc");
  });
});

class BindingRecoveryTransport implements MutationTransport {
  public readonly requests: HttpRequest[] = [];
  private role = "admin";
  public constructor(private readonly actorId = "actor-1") {}
  public async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    if (request.method === "PATCH") this.role = "user";
    const body = new URL(request.url).pathname === "/api/session/me" ? { actor: { id: this.actorId } } : { object: { id: "target-1" }, state: { role: this.role } };
    return response(request, body);
  }
}

class CountingTransport implements MutationTransport {
  public requests: HttpRequest[] = [];
  public async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    const body = request.method === "GET" ? { id: "target-1", role: "user" } : { accepted: true };
    const serialized = JSON.stringify(body);
    return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: createHash("sha256").update(serialized).digest("hex"), responseTimeMs: 1, redirectChain: [] };
  }
}

function validContract() {
  return {
    schemaVersion: 1 as const, caseId: "binding-case", targetOrigin: "https://example.test", mode: "CONTROLLED_MUTATION" as const, environment: "STAGING" as const, productionAcknowledged: false,
    authorization: { authorizedBy: "owner", changeTicket: "SEC-1", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY" as const, authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
    target: { disposable: true as const, type: "user", alias: "target", identityFingerprint: createHash("sha256").update(JSON.stringify("target-1")).digest("hex"), identityAssertion: { path: "id", operator: "EQUALS" as const, expectedValue: "target-1" } },
    attack: { request: request("PATCH", "{\"role\":\"admin\"}"), allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" as const },
    precondition: { request: request("GET"), assertions: [{ path: "id", operator: "EQUALS" as const, expectedValue: "target-1" }, { path: "role", operator: "EQUALS" as const, expectedValue: "user" }], attempts: 1, delayMs: 0 },
    impact: { request: request("GET"), assertions: [{ path: "role", operator: "EQUALS" as const, expectedValue: "user" }], attempts: 1, delayMs: 0 },
    rollback: { request: request("PATCH", "{\"role\":\"user\"}"), verification: { request: request("GET"), matchPreStateHash: false, assertions: [{ path: "role", operator: "EQUALS" as const, expectedValue: "user" }], attempts: 1, delayMs: 0 } }
  };
}
function request(method: "GET" | "PATCH", body?: string): HttpRequest { return { url: "https://example.test/api/target-1", method, ...(body ? { body } : {}) }; }
async function tempDirectory(): Promise<string> { return mkdtemp(join(tmpdir(), "routecairn-binding-")); }
function hash(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function response(request: HttpRequest, body: unknown): HttpResponse { const serialized = JSON.stringify(body); return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: createHash("sha256").update(serialized).digest("hex"), responseTimeMs: 1, redirectChain: [] }; }
