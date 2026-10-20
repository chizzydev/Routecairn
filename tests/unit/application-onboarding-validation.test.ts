import { it, expect } from "vitest";
import { applicationOnboardingSchema } from "../../src/dashboard/contracts/ApplicationOnboardingContracts.js";
it("returns validation failures rather than throwing on empty, malformed or credential-bearing origins", () => {
  const actor = {
    principal: "p",
    tenant: "north",
    role: "member",
    authorizationHeader: "Bearer owned-fixture",
    expiresAt: "2099-01-01T00:00:00Z"
  };
  for (const origin of ["", "garbage", "http://", "http://user:pass@127.0.0.1:3000"]) {
    const input = {
      displayName: "Owned",
      origin,
      authorizationSummary: "Disposable owner authorization",
      identityPath: "/identity",
      seedPath: "/catalog",
      principalField: "principal",
      tenantField: "tenant",
      roleField: "role",
      objectField: "id",
      objectTenantField: "tenant",
      actors: {
        primary: { ...actor, principal: "p" },
        account_a: { ...actor, principal: "a" },
        account_b: { ...actor, principal: "b" }
      },
      ownedReadOnlyConfirmed: true
    };
    let result: ReturnType<typeof applicationOnboardingSchema.safeParse> | undefined;
    expect(() => {
      result = applicationOnboardingSchema.safeParse(input);
    }).not.toThrow();
    expect(result?.success).toBe(false);
  }
});
