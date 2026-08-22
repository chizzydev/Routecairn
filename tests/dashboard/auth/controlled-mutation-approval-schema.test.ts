import { describe, expect, it } from "vitest";
import { controlledMutationApprovalSchema } from "../../../src/dashboard/contracts/ControlledMutationSchemas.js";

describe("controlled mutation approval schema", () => {
  it("requires explicit case, target, plan identity, expiry, and cleanup confirmation", () => {
    const parsed = controlledMutationApprovalSchema.parse({ caseId: "case-1", targetId: "00000000-0000-4000-8000-000000000001", targetOrigin: "https://example.test", planIdentity: "a".repeat(64), authorizationDeclaration: "Owned staging environment for security testing", expiresAt: "2099-01-01T00:00:00.000Z", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY" });
    expect(parsed.caseId).toBe("case-1");
  });

  it("rejects approval without cleanup confirmation", () => {
    expect(() => controlledMutationApprovalSchema.parse({ caseId: "case-1", targetId: "00000000-0000-4000-8000-000000000001", targetOrigin: "https://example.test", planIdentity: "a".repeat(64), authorizationDeclaration: "Owned staging environment for security testing", expiresAt: "2099-01-01T00:00:00.000Z" })).toThrow();
  });
});
