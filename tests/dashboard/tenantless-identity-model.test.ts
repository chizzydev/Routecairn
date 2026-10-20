import { it, expect } from "vitest";
import { applicationOnboardingSchema } from "../../src/dashboard/contracts/ApplicationOnboardingContracts.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
export const tenantlessInput = () => ({
  displayName: "Generated principal role application",
  origin: "http://127.0.0.1:9000",
  identityModel: "PRINCIPAL_ROLE",
  authorizationSummary: "Owner authorizes separately reviewed synthetic GET observations",
  identityPath: "/identity",
  principalField: "id",
  roleField: "role",
  seedPath: "/object",
  objectField: "id",
  actors: Object.fromEntries(
    ["primary", "account_a", "account_b"].map((slot, i) => [
      slot,
      {
        principal: "person-" + i,
        role: i === 0 ? "admin" : "user",
        authorizationHeader: "Bearer generated-" + slot,
        expiresAt: "2099-01-01T00:00:00Z"
      }
    ])
  ),
  ownedReadOnlyConfirmed: true
});
it("represents explicitly tenantless onboarding without synthesizing any tenant", () => {
  const result = applicationOnboardingSchema.safeParse(tenantlessInput());
  expect(result.success).toBe(true);
  if (result.success) expect(result.data).toMatchObject({ identityModel: "PRINCIPAL_ROLE" });
});
it("retains explicit native principal-role mode instead of dropping it while parsing credentials", () => {
  const p = authProfileSchema.parse({
    identityModel: "PRINCIPAL_ROLE",
    principalId: "person-0",
    role: "admin",
    identityVerification: { mode: "required", endpoint: "/identity", principalIdField: "id", roleField: "role" }
  });
  expect(p).toHaveProperty("identityModel", "PRINCIPAL_ROLE");
});
