import { describe, expect, it } from "vitest";
import { controlledMutationContractSchema } from "../../src/core/offensive/ControlledMutationTypes.js";
import { apiToWorkerMessageSchema, workerProtocolVersion } from "../../src/dashboard/worker/ScanWorkerProtocol.js";

describe("worker controlled mutation contract transport", () => {
  it("accepts a bounded contract envelope message shape", () => {
    const result = apiToWorkerMessageSchema.parse({
      protocolVersion: workerProtocolVersion,
      type: "PROVIDE_MUTATION_CONTRACTS",
      workerId: "00000000-0000-4000-8000-000000000001",
      jobId: "00000000-0000-4000-8000-000000000002",
      sequence: 2,
      expiresAt: "2099-01-01T00:00:00.000Z",
      nonce: "nonce-1234567890123456",
      contracts: [controlledMutationContractSchema.parse({
        schemaVersion: 1, caseId: "case-1", targetOrigin: "https://example.test", mode: "CONTROLLED_MUTATION", environment: "STAGING", productionAcknowledged: false,
        authorization: { authorizedBy: "owner", changeTicket: "SEC-1", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
        target: { disposable: true, type: "user", alias: "target", identityFingerprint: "a".repeat(64), identityAssertion: { path: "id", operator: "EQUALS", expectedValue: "target" } },
        attack: { request: { url: "https://example.test/user/target", method: "PATCH", body: "{\"role\":\"admin\"}" }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" },
        precondition: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "id", operator: "EQUALS", expectedValue: "target" }], attempts: 1, delayMs: 0 },
        impact: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }], attempts: 1, delayMs: 0 },
        rollback: { request: { url: "https://example.test/user/target", method: "PATCH", body: "{\"role\":\"user\"}" }, verification: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 } }
      })],
      hmac: "a".repeat(64)
    });
    expect(result.type).toBe("PROVIDE_MUTATION_CONTRACTS");
  });

  it("rejects an unbounded contract batch", () => {
    expect(() => apiToWorkerMessageSchema.parse({ protocolVersion: workerProtocolVersion, type: "PROVIDE_MUTATION_CONTRACTS", workerId: "00000000-0000-4000-8000-000000000001", jobId: "00000000-0000-4000-8000-000000000002", sequence: 2, expiresAt: "2099-01-01T00:00:00.000Z", nonce: "nonce-1234567890123456", contracts: [], hmac: "a".repeat(64) })).toThrow();
  });
});
