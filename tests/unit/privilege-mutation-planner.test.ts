import { describe, expect, it } from "vitest";
import { planPrivilegeMutationTesting, privilegeMutationInputSchema } from "../../src/modules/privilegeMutation/PrivilegeMutationPlanner.js";

describe("privilege mutation planner", () => {
  it("accepts an explicitly bounded authority-field case", () => {
    const input = privilegeMutationInputSchema.parse({
      schemaVersion: 1,
      cases: [{
        caseId: "role-boundary-1",
        category: "PRIVILEGE_ESCALATION",
        actor: { label: "low-privilege", relationship: "LOWER_PRIVILEGED_ROLE" },
        target: { type: "user", alias: "disposable-user", identityFingerprint: "a".repeat(64), identityRequest: { url: "https://example.test/api/me", method: "GET" }, identityAssertions: [{ path: "id", operator: "EQUALS", expectedValue: "disposable-1" }] },
        attack: { request: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: "{\"role\":\"admin\"}" }, field: "role", value: "admin", allowedValues: ["admin"] },
        originalAuthority: { request: { url: "https://example.test/api/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] },
        impact: { request: { url: "https://example.test/api/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }] },
        rollback: { request: { url: "https://example.test/api/users/disposable-1", method: "PATCH", body: "{\"role\":\"user\"}" }, verification: { request: { url: "https://example.test/api/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] } }
      }]
    });
    const plan = planPrivilegeMutationTesting(input, { target: "https://example.test", maxCases: 5 });
    expect(plan.enabled).toBe(true);
    expect(plan.cases[0]?.attack.field).toBe("role");
    expect(plan.cases[0]?.attack.valueHash).toHaveLength(64);
    expect((plan.cases[0]?.attack as Record<string, unknown>).request).toBeUndefined();
    expect(JSON.stringify(plan.cases[0])).not.toContain('{"role":"user"}');
    expect(plan.maxRequests).toBe(11);
  });

  it("rejects an authority mutation with more than one body field", () => {
    expect(() => privilegeMutationInputSchema.parse({
      schemaVersion: 1,
      cases: [{
        caseId: "bad", category: "MASS_ASSIGNMENT", actor: { label: "actor", relationship: "LOWER_PRIVILEGED_ROLE" },
        target: { type: "user", alias: "target", identityFingerprint: "b".repeat(64), identityRequest: { url: "https://example.test/me", method: "GET" }, identityAssertions: [{ path: "id", operator: "EQUALS", expectedValue: "x" }] },
        attack: { request: { url: "https://example.test/user/x", method: "PATCH", body: "{\"role\":\"admin\",\"status\":\"approved\"}" }, field: "role", value: "admin", allowedValues: ["admin"] },
        originalAuthority: { request: { url: "https://example.test/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] },
        impact: { request: { url: "https://example.test/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }] },
        rollback: { request: { url: "https://example.test/user/x", method: "PATCH", body: "{\"role\":\"user\"}" }, verification: { request: { url: "https://example.test/me", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }] } }
      }]
    })).toThrow();
  });
});
