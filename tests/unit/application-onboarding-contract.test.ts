import { it, expect } from "vitest";
import { applicationOnboardingSchema } from "../../src/dashboard/contracts/ApplicationOnboardingContracts.js";
const input = () => ({
  displayName: "Owned local app",
  origin: "http://127.0.0.1:9000",
  authorizationSummary: "Owned application with separately reviewed safe GET observations",
  identityPath: "/identity",
  principalField: "principal",
  tenantField: "tenant",
  roleField: "role",
  seedPath: "/ledger/start",
  objectField: "record.entryId",
  objectTenantField: "record.book",
  actors: Object.fromEntries(
    ["primary", "account_a", "account_b"].map((slot) => [
      slot,
      {
        principal: slot,
        tenant: slot === "account_b" ? "south" : "north",
        role: slot,
        authorizationHeader: "Bearer disposable-" + slot,
        expiresAt: "2099-01-01T00:00:00Z"
      }
    ])
  ),
  ownedReadOnlyConfirmed: true
});
it("admits only declarations with all three distinct future-bound actor contracts", () => {
  expect(applicationOnboardingSchema.parse(input()).actors.account_b.tenant).toBe("south");
});
it.each(["expired", "sensitive-marker", "origin-alias", "userinfo", "header-newline"])(
  "refuses %s before any persistence or transmission",
  (fault) => {
    const v = input();
    if (fault === "expired") v.actors.primary!.expiresAt = "2000-01-01T00:00:00Z";
    if (fault === "sensitive-marker") v.objectField = "record.secret";
    if (fault === "origin-alias") v.origin = "http://127.000.000.001:9000";
    if (fault === "userinfo") v.origin = "http://name@127.0.0.1:9000";
    if (fault === "header-newline") v.actors.primary!.authorizationHeader = "Bearer disposable\r\nInjected: value";
    expect(applicationOnboardingSchema.safeParse(v).success).toBe(false);
  }
);
