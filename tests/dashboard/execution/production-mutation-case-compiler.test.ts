import { describe, expect, it } from "vitest";
import { compileProductionMutationCase, productionMutationPlanIdentity } from "../../../src/dashboard/execution/ProductionMutationCaseCompiler.js";
import { productionMutationCaseSchema } from "../../../src/dashboard/contracts/ProductionMutationCaseSchemas.js";
import { approvedMutationPlan } from "../../../src/dashboard/execution/ApprovedMutationPlan.js";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { mutationContractMessage } from "../../../src/dashboard/worker/ScanWorkerManager.js";
import { parseApiMessage } from "../../../src/dashboard/worker/ScanWorkerProtocol.js";
import { ControlledMutationExecutor } from "../../../src/core/offensive/ControlledMutationExecutor.js";
import type { HttpRequest, HttpResponse } from "../../../src/core/http/HttpTypes.js";
import type { MutationTransport } from "../../../src/core/offensive/ControlledMutationTypes.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrivilegeMutationModule } from "../../../src/modules/privilegeMutation/PrivilegeMutationModule.js";

const input = productionMutationCaseSchema.parse({ schemaVersion: 1, caseId: "prod-role-001", targetId: "00000000-0000-4000-8000-000000000001", environment: "PRODUCTION", productionAcknowledged: true, actorCredentialProfileId: "00000000-0000-4000-8000-000000000002", disposableTargetAlias: "test-user-001", authorityField: "role", mutationValue: "admin", allowedValues: ["admin"], identity: { method: "GET", path: "/api/session/me", assertions: [{ path: "actor.id", operator: "EQUALS", expectedValue: "actor-001" }, { path: "actor.enabled", operator: "EQUALS", expectedValue: true }] }, actorIdentityAssertionPath: "actor.id", precondition: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "object.id", operator: "EQUALS", expectedValue: "test-user-001" }, { path: "state.role", operator: "EQUALS", expectedValue: "user" }] }, disposableObjectIdentityAssertionPath: "object.id", mutation: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "admin" } }, impactVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "state.role", operator: "EQUALS", expectedValue: "admin" }] }, rollback: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "user" } }, restorationVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "state.role", operator: "EQUALS", expectedValue: "user" }] }, authorizationExpiresAt: "2099-01-01T00:00:00.000Z" });
const target = { id: input.targetId, displayName: "Production", baseOrigin: "https://app.example.com", productionEnabled: true, approvedScope: { program: "https://app.example.com", allowedDomains: ["app.example.com"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], sameOriginOnly: true, includeSubdomains: false, rateLimitPerSecond: 1, concurrency: 1, maxRequests: 100, userAgent: "RouteCairn", bodyPreviewBytes: 1024, maxResponseBytes: 1024 } } as any;

describe("production mutation compiler", () => {
  it("compiles separate actor identity and object precondition contracts with explicit JSON semantics", () => { const result = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner"); expect(result.contract.identity?.request.url).toBe("https://app.example.com/api/session/me"); expect(result.contract.precondition.request.url).toBe("https://app.example.com/api/users/test-user-001"); expect(result.contract.identity?.assertions.map((value) => value.path)).toEqual(["actor.id", "actor.enabled"]); expect(result.contract.precondition.assertions.map((value) => value.path)).toEqual(["object.id", "state.role"]); expect(result.contract.attack.request.headers?.["content-type"]).toBe("application/json"); expect(result.contract.rollback.request.headers?.["content-type"]).toBe("application/json"); expect(result.preview.endpoints).toContain("/api/session/me"); expect(JSON.stringify(result.preview)).not.toContain("admin"); });
  it("rejects a target that is not classified production", () => { expect(() => compileProductionMutationCase(input, { ...target, productionEnabled: false }, "2026-01-01T00:00:00.000Z", "owner")).toThrow("PRODUCTION_TARGET_REQUIRED"); });
  it("derives exact execution semantics without request credentials or bodies", () => {
    const { contract } = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner");
    contract.attack.request.headers = { authorization: "fixture-secret-sentinel" };
    const plan = approvedMutationPlan([contract]);
    expect(plan.cases[0]?.attack.allowedValuesHash).toBe(createHash("sha256").update(JSON.stringify({ role: ["admin"] })).digest("hex"));
    expect(plan.cases[0]?.rollback.request.bodyHash).toBe(createHash("sha256").update(JSON.stringify(contract.rollback.request.body)).digest("hex"));
    expect(plan.maxRequests).toBe(14);
    expect(plan.cases[0]?.actor.identityRequest?.url).toBe("https://app.example.com/api/session/me");
    expect(JSON.stringify(plan)).not.toContain("fixture-secret-sentinel");
    expect(() => approvedMutationPlan([contract, contract])).toThrow("DUPLICATE_CASE");
    expect(() => approvedMutationPlan([{ ...contract, attack: { ...contract.attack, semanticEffect: "DELETE" } }])).toThrow("CONTRACT_INVALID");
  });
  it("executes identity before a differently shaped precondition and preserves both bindings", async () => {
    const { contract } = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner");
    const transport = new ProductionTransport();
    const directory = await mkdtemp(join(tmpdir(), "routecairn-production-identity-"));
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: directory, sleep: async () => undefined }).execute(contract);
    expect(transport.requests.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual(["GET /api/session/me", "GET /api/users/test-user-001", "PATCH /api/users/test-user-001", "GET /api/users/test-user-001", "PATCH /api/users/test-user-001", "GET /api/users/test-user-001"]);
    expect(result).toMatchObject({ securityOutcome: "EXPLOIT_PROVEN", cleanupOutcome: "ROLLBACK_VERIFIED" });
    expect(result.actorIdentityResponseHash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.targetIdentityResponseHash).toMatch(/^[a-f0-9]{64}$/);
    expect(transport.requests.filter((request) => request.method === "PATCH").every((request) => request.headers?.["content-type"] === "application/json")).toBe(true);
  });
  it("stops at the exact identity endpoint when the configured actor assertions fail", async () => {
    const { contract } = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner");
    const transport = new ProductionTransport("different-actor");
    const result = await new ControlledMutationExecutor(transport, { journalDirectory: await mkdtemp(join(tmpdir(), "routecairn-production-identity-reject-")), sleep: async () => undefined }).execute(contract);
    expect(result).toMatchObject({ securityOutcome: "INCONCLUSIVE", cleanupOutcome: "NOT_REQUIRED" });
    expect(transport.requests).toHaveLength(contract.identity?.attempts ?? 0);
    expect(transport.requests.every((request) => new URL(request.url).pathname === "/api/session/me" && request.method === "GET")).toBe(true);
  });
  it("authenticates normalized contracts regardless of optional field insertion order", () => {
    const { contract } = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner");
    const bound = { ...contract, approvalBinding: { scopeDigest: "a".repeat(64), planIdentity: "b".repeat(64), targetIdentityFingerprint: "c".repeat(64) } };
    const message = mutationContractMessage({ workerId: randomUUID(), jobId: randomUUID(), workerSecret: "fixture-secret", contracts: [bound] });
    const parsed = parseApiMessage(JSON.parse(JSON.stringify(message)));
    if (parsed.type !== "PROVIDE_MUTATION_CONTRACTS") throw new Error("Wrong message");
    const { hmac, ...payload } = parsed;
    expect(hmac).toBe(createHmac("sha256", "fixture-secret").update(JSON.stringify(payload)).digest("hex"));
  });
  it("binds intent into approvals and never reports an authorized acceptance transition as a vulnerability", async () => {
    const acceptanceInput = productionMutationCaseSchema.parse({ ...input, intent: "ROLLBACK_ACCEPTANCE" });
    const security = compileProductionMutationCase(input, target, "2026-01-01T00:00:00.000Z", "owner");
    const acceptance = compileProductionMutationCase(acceptanceInput, target, "2026-01-01T00:00:00.000Z", "owner");
    expect(productionMutationPlanIdentity(input, target)).not.toBe(productionMutationPlanIdentity(acceptanceInput, target));
    expect(acceptance.preview).toMatchObject({ intent: "ROLLBACK_ACCEPTANCE", expectedOutcome: "MUST_SUCCEED_AND_RESTORE" });
    const plan = approvedMutationPlan([acceptance.contract]);
    const result = await new PrivilegeMutationModule().run({
      options: { plan: { privilegeMutationTesting: plan }, controlledMutationContracts: [acceptance.contract] },
      runControlledMutation: async () => ({ caseId: acceptance.contract.caseId, outcome: "EXPECTED_MUTATION_VERIFIED", securityOutcome: "EXPECTED_MUTATION_VERIFIED", cleanupOutcome: "ROLLBACK_VERIFIED", preStateHash: "a".repeat(64), targetIdentityResponseHash: "b".repeat(64), verificationResponseHash: "c".repeat(64), attackResponseHash: "d".repeat(64), journalPath: "redacted", comparisonIdentity: "e".repeat(64), notes: [] })
    } as any);
    expect(result.findings).toHaveLength(0);
    expect(result.privilegeMutation?.observations[0]).toMatchObject({ intent: "ROLLBACK_ACCEPTANCE", securityOutcome: "MUTATION_ACCEPTED_WITHOUT_SECURITY_IMPACT", authorityChangeVerified: true, cleanupOutcome: "ROLLBACK_VERIFIED" });
    const securityExecution = await new ControlledMutationExecutor(new ProductionTransport(), { journalDirectory: await mkdtemp(join(tmpdir(), "routecairn-security-intent-")), sleep: async () => undefined }).execute(security.contract);
    const acceptanceExecution = await new ControlledMutationExecutor(new ProductionTransport(), { journalDirectory: await mkdtemp(join(tmpdir(), "routecairn-acceptance-intent-")), sleep: async () => undefined }).execute(acceptance.contract);
    expect(securityExecution.comparisonIdentity).not.toBe(acceptanceExecution.comparisonIdentity);
    expect(securityExecution.securityOutcome).toBe("EXPLOIT_PROVEN");
    expect(acceptanceExecution.securityOutcome).toBe("EXPECTED_MUTATION_VERIFIED");
    expect(security.contract.intent).toBe("SECURITY_NEGATIVE");
  });
});

class ProductionTransport implements MutationTransport {
  public readonly requests: HttpRequest[] = [];
  private role = "user";
  public constructor(private readonly actorId = "actor-001") {}
  public async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    if (request.method === "PATCH") this.role = (JSON.parse(request.body ?? "{}") as { role?: string }).role ?? this.role;
    const body = new URL(request.url).pathname === "/api/session/me" ? { actor: { id: this.actorId, enabled: true }, session: { kind: "authenticated" } } : { object: { id: "test-user-001" }, state: { role: this.role }, revision: 7 };
    const serialized = JSON.stringify(body);
    return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: createHash("sha256").update(serialized).digest("hex"), responseTimeMs: 1, redirectChain: [] };
  }
}
