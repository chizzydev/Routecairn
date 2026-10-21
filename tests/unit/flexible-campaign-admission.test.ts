import { it, expect } from "vitest";
import { prepareProductionWebCampaign } from "../../src/cli/commands/webAssessment.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
it("admits an explicitly versioned one-account existing-test production contract without demanding three fresh accounts", () => {
  const input = prepareProductionWebCampaign("https://owned.example.test/", "Owned synthetic flexible contract");
  const old = input.authorization.productionCampaign!;
  const { identities: _, disposableAccountsSupplied: __, ...base } = old;
  const value = {
    ...input.authorization,
    productionCampaign: {
      ...base,
      contractVersion: 2,
      authenticationPermitted: true,
      workflows: ["AUTHENTICATED_READ_ONLY"],
      effects: { sessionHousekeeping: "SESSION_LAST_USED_AT_UPDATE", approved: true },
      actorRegistryDigest: "a".repeat(64),
      actorIds: ["one"],
      workflowAuthorizations: [
        { id: "one-read", family: "AUTHENTICATED_OBSERVATION", actorIds: ["one"], reviewed: true }
      ]
    }
  };
  expect(targetAuthorizationSchema.safeParse(value).success).toBe(true);
});
