import { it, expect } from "vitest";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
it("does not verify a declared role by mapping the principal field as role evidence", () => {
  const input = {
    identityModel: "PRINCIPAL_ROLE",
    principalId: "person",
    role: "person",
    identityVerification: { mode: "required", endpoint: "/identity", principalIdField: "id", roleField: "id" }
  };
  expect(authProfileSchema.safeParse(input).success).toBe(false);
});
