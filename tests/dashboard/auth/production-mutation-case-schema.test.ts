import { describe, expect, it } from "vitest";
import { productionMutationCaseSchema } from "../../../src/dashboard/contracts/ProductionMutationCaseSchemas.js";

describe("production mutation case schema", () => {
  it("accepts a fully explicit reversible production case", () => {
    const parsed = productionMutationCaseSchema.parse({
      schemaVersion: 1, caseId: "prod-role-001", targetId: "00000000-0000-4000-8000-000000000001", environment: "PRODUCTION", productionAcknowledged: true,
      actorCredentialProfileId: "00000000-0000-4000-8000-000000000002", disposableTargetAlias: "test-user-001", authorityField: "role", mutationValue: "admin", allowedValues: ["admin"],
      identity: { method: "GET", path: "/api/session/me", assertions: [{ path: "actor.id", operator: "EQUALS", expectedValue: "actor-001" }] }, actorIdentityAssertionPath: "actor.id",
      precondition: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "object.id", operator: "EQUALS", expectedValue: "test-user-001" }, { path: "state.role", operator: "EQUALS", expectedValue: "user" }] }, disposableObjectIdentityAssertionPath: "object.id",
      mutation: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "admin" } },
      impactVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }] },
      protectedAction: { method: "GET", path: "/api/admin/users", assertions: [{ path: "access", operator: "EQUALS", expectedValue: "granted" }] },
      rollback: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "user" } },
      restorationVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] },
      authorizationExpiresAt: "2099-01-01T00:00:00.000Z"
    });
    expect(parsed.environment).toBe("PRODUCTION");
    expect(parsed.identity.path).not.toBe(parsed.precondition.path);
  });

  it("rejects ambiguous actor or disposable-object bindings", () => {
    const base = { schemaVersion: 1, caseId: "prod-role-001", targetId: "00000000-0000-4000-8000-000000000001", environment: "PRODUCTION", productionAcknowledged: true, actorCredentialProfileId: "00000000-0000-4000-8000-000000000002", disposableTargetAlias: "test-user-001", authorityField: "role", mutationValue: "admin", allowedValues: ["admin"], identity: { method: "GET", path: "/api/session/me", assertions: [{ path: "actor.id", operator: "EQUALS", expectedValue: "actor-001" }] }, actorIdentityAssertionPath: "actor.missing", precondition: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "object.id", operator: "EQUALS", expectedValue: "test-user-001" }, { path: "state.role", operator: "EQUALS", expectedValue: "user" }] }, disposableObjectIdentityAssertionPath: "object.id", mutation: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "admin" } }, impactVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "state.role", operator: "EQUALS", expectedValue: "admin" }] }, rollback: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "user" } }, restorationVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "state.role", operator: "EQUALS", expectedValue: "user" }] }, authorizationExpiresAt: "2099-01-01T00:00:00.000Z" };
    expect(() => productionMutationCaseSchema.parse(base)).toThrow(/Actor identity binding/);
    expect(() => productionMutationCaseSchema.parse({ ...base, actorIdentityAssertionPath: "actor.id", disposableObjectIdentityAssertionPath: "object.missing" })).toThrow(/Disposable object binding/);
  });

  it("rejects an external endpoint and an unacknowledged production case", () => {
    expect(() => productionMutationCaseSchema.parse({ schemaVersion: 1, caseId: "prod-role-001", targetId: "00000000-0000-4000-8000-000000000001", environment: "PRODUCTION", productionAcknowledged: false, actorCredentialProfileId: "00000000-0000-4000-8000-000000000002", disposableTargetAlias: "test-user-001", authorityField: "role", mutationValue: "admin", allowedValues: ["admin"], identity: { method: "GET", path: "https://evil.example/users/test-user-001", assertions: [{ path: "id", operator: "EQUALS", expectedValue: "test-user-001" }] }, precondition: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] }, mutation: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "admin" } }, impactVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }] }, rollback: { method: "PATCH", path: "/api/users/test-user-001", body: { role: "user" } }, restorationVerification: { method: "GET", path: "/api/users/test-user-001", assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] }, authorizationExpiresAt: "2099-01-01T00:00:00.000Z" })).toThrow();
  });
});
