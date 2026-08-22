import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { HttpRequest, HttpResponse } from "../../src/core/http/HttpTypes.js";
import { ControlledMutationExecutor } from "../../src/core/offensive/ControlledMutationExecutor.js";
import { controlledMutationContractSchema, type MutationTransport } from "../../src/core/offensive/ControlledMutationTypes.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { MutationJournal } from "../../src/core/offensive/MutationJournal.js";

describe("Batch 41 adversarial closure matrix", () => {
  it("rejects missing and corrupted recovery bundles without transmitting rollback", async () => {
    const directory = await tempDirectory();
    const transport = new RecordingTransport();
    const executor = new ControlledMutationExecutor(transport, { journalDirectory: directory });
    await expect(executor.recover(join(directory, "missing.recovery.enc"), "missing-case")).rejects.toThrow();
    const corrupted = join(directory, "corrupted.recovery.enc");
    await writeFile(corrupted, "not-an-encrypted-bundle", "utf8");
    await expect(executor.recover(corrupted, "corrupted-case")).rejects.toThrow();
    expect(transport.requests).toHaveLength(0);
  });

  it("preserves the recovery bundle after partial rollback and reports cleanup failure", async () => {
    const directory = await tempDirectory();
    const vault = new MutationRecoveryVault(directory);
    const bundlePath = await vault.seal(bundle("partial-rollback"));
    const transport = new RecordingTransport({ rollbackFails: true, initialRole: "admin" });
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory }).recover(bundlePath, "partial-rollback");
    expect(result.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(await readdir(directory)).toContain("partial-rollback.recovery.enc");
  });

  it("classifies redirect responses and transport timeouts as inconclusive without false proof", async () => {
    const redirect = new RecordingTransport({ responseOverride: (request) => response(request, 302, { location: "https://other.example/changed" }, { location: "https://other.example/changed" }) });
    const redirectResult = await new ControlledMutationExecutor(redirect, { journalDirectory: await tempDirectory() }).execute(contract());
    expect(redirectResult.securityOutcome).toBe("INCONCLUSIVE");
    const timeout = new RecordingTransport({ errorName: "TimeoutError" });
    const timeoutResult = await new ControlledMutationExecutor(timeout, { journalDirectory: await tempDirectory() }).execute(contract());
    expect(timeoutResult.securityOutcome).toBe("INCONCLUSIVE");
  });

  it("requires nested authority assertions and does not accept an actor-role mismatch", async () => {
    const nested = contract({ preconditionAssertions: [{ path: "id", operator: "EQUALS", expectedValue: "target-1" }, { path: "profile.role", operator: "EQUALS", expectedValue: "user" }], impactAssertions: [{ path: "profile.role", operator: "EQUALS", expectedValue: "admin" }] });
    const transport = new RecordingTransport({ body: { id: "target-1", profile: { role: "user" } } });
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: await tempDirectory() }).execute(nested);
    expect(result.securityOutcome).toBe("INCONCLUSIVE");
    const mismatch = await new ControlledMutationExecutor(new RecordingTransport({ body: { id: "target-1", profile: { role: "admin" } } }), { journalDirectory: await tempDirectory() }).execute(contract());
    expect(mismatch.securityOutcome).toBe("INCONCLUSIVE");
  });

  it("redacts secrets and bodies from journals, recovery status material, and event-like output", async () => {
    const directory = await tempDirectory();
    const secretBody = '{"role":"admin","token":"super-secret-token"}';
    const result = await new ControlledMutationExecutor(new RecordingTransport(), { journalDirectory: directory }).execute(contract({ attackBody: secretBody }));
    const journal = await readFile(join(directory, "mutation-journal.json"), "utf8");
    expect(journal).not.toContain("super-secret-token");
    expect(journal).not.toContain('"role":"admin"');
    expect(JSON.stringify(result)).not.toContain("super-secret-token");
  });

  it("records every durable journal boundary in order and leaves recovery material on injected crash", async () => {
    const directory = await tempDirectory();
    const journalPath = join(directory, "mutation-journal.json");
    const originalAppend = MutationJournal.prototype.append;
    MutationJournal.prototype.append = async function (entry) {
      await originalAppend.call(this, entry);
      if (entry.stage === "MUTATION_SENT") throw new Error("injected crash after transmission");
    };
    try {
      const result = await new ControlledMutationExecutor(new RecordingTransport(), { journalDirectory: directory }).execute(contract());
      expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
      const entries = await new MutationJournal(journalPath).read();
      expect(entries.map((entry) => entry.stage)).toEqual(expect.arrayContaining(["AUTHORIZED", "PRE_STATE_CAPTURED", "MUTATION_ARMED", "MUTATION_SENT", "ROLLBACK_SENT", "ROLLBACK_VERIFIED"]));
    } finally { MutationJournal.prototype.append = originalAppend; }
  });
});

class RecordingTransport implements MutationTransport {
  public requests: HttpRequest[] = [];
  private role: string;
  public constructor(private readonly options: { rollbackFails?: boolean; responseOverride?: (request: HttpRequest) => HttpResponse; errorName?: string; body?: unknown; initialRole?: string } = {}) { this.role = options.initialRole ?? "user"; }
  public async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    if (this.options.errorName) return { ...response(request, 0, {}), error: { name: this.options.errorName, message: "transport failure" } };
    if (this.options.responseOverride) return this.options.responseOverride(request);
    if (request.method !== "GET") {
      if (this.options.rollbackFails && JSON.parse(request.body ?? "{}").role === "user") return response(request, 500, { error: "rollback unavailable" });
      const body = JSON.parse(request.body ?? "{}") as { role?: string };
      if (body.role) this.role = body.role;
      return response(request, 200, { accepted: true });
    }
    return response(request, 200, this.options.body ?? { id: "target-1", role: this.role });
  }
}

function contract(overrides: { preconditionAssertions?: Array<{ path: string; operator: "EQUALS"; expectedValue: unknown }>; impactAssertions?: Array<{ path: string; operator: "EQUALS"; expectedValue: unknown }>; attackBody?: string } = {}) {
  const raw = {
    schemaVersion: 1, caseId: "closure-case", targetOrigin: "https://example.test", mode: "CONTROLLED_MUTATION", environment: "STAGING", productionAcknowledged: false,
    authorization: { authorizedBy: "owner", changeTicket: "SEC-CLOSURE", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
    target: { disposable: true, type: "user", alias: "target", identityFingerprint: hash("target-1"), identityAssertion: { path: "id", operator: "EQUALS", expectedValue: "target-1" } },
    attack: { request: { url: "https://example.test/api/target-1", method: "PATCH", body: overrides.attackBody ?? '{"role":"admin"}' }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" },
    precondition: { request: { url: "https://example.test/api/target-1", method: "GET" }, assertions: overrides.preconditionAssertions ?? [{ path: "id", operator: "EQUALS", expectedValue: "target-1" }, { path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 },
    impact: { request: { url: "https://example.test/api/target-1", method: "GET" }, assertions: overrides.impactAssertions ?? [{ path: "role", operator: "EQUALS", expectedValue: "admin" }], attempts: 1, delayMs: 0 },
    rollback: { request: { url: "https://example.test/api/target-1", method: "PATCH", body: '{"role":"user"}' }, verification: { request: { url: "https://example.test/api/target-1", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 } }
  };
  return controlledMutationContractSchema.parse(raw);
}
function bundle(caseId: string) { return { caseId, targetOrigin: "https://example.test", targetIdentityFingerprint: hash("target-1"), authorizationExpiresAt: "2099-01-01T00:00:00.000Z", contractDigest: hash(caseId), rollbackRequest: { url: "https://example.test/api/target-1", method: "PATCH", body: '{"role":"user"}' }, rollbackVerification: { request: { url: "https://example.test/api/target-1", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 } }; }
function response(request: HttpRequest, statusCode: number, body: unknown, headers: Record<string, string> = { "content-type": "application/json" }): HttpResponse { const serialized = JSON.stringify(body); return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode, headers, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: hash(body), responseTimeMs: 1, redirectChain: [] }; }
function hash(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
async function tempDirectory(): Promise<string> { return mkdtemp(join(tmpdir(), "routecairn-closure-")); }
