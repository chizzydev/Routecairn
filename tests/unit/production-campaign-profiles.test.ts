import { it, expect } from "vitest";
import { createHash } from "node:crypto";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import {
  assertProductionCampaignProfiles,
  productionCampaignSchema,
  productionCredentialDigest
} from "../../src/core/authorization/ProductionCampaign.js";
import { prepareProductionWebCampaign } from "../../src/cli/commands/webAssessment.js";
const fp = (s: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + s)
    .digest("hex")
    .slice(0, 16);
it.each(["TENANT_AWARE", "PRINCIPAL_ROLE"] as const)(
  "binds three fresh declared %s profile slots and rejects replacement",
  (model) => {
    const profiles = ["primary", "account_a", "account_b"].map((slot, i) =>
      authProfileSchema.parse({
        identityModel: model,
        label: slot,
        principalId: "fixture-" + i,
        role: "member",
        ...(model === "TENANT_AWARE" ? { tenantId: "fixture-tenant" } : {}),
        headers: { authorization: "Bearer fixture-only-" + i },
        identityVerification: {
          mode: "required",
          endpoint: "https://owned.example.test/me",
          principalIdField: "id",
          roleField: "role",
          ...(model === "TENANT_AWARE" ? { tenantIdField: "tenant" } : {})
        }
      })
    );
    const p = prepareProductionWebCampaign("https://owned.example.test/", "Synthetic three profile binding")
      .authorization.productionCampaign!;
    const campaign = productionCampaignSchema.parse({
      ...p,
      authenticationPermitted: true,
      disposableAccountsSupplied: true,
      workflows: ["AUTHENTICATED_READ_ONLY"],
      effects: { sessionHousekeeping: "SESSION_LAST_USED_AT_UPDATE", approved: true },
      identities: profiles.map((profile, i) => ({
        slot: ["primary", "account_a", "account_b"][i],
        identityModel: model,
        principalFingerprint: fp(profile.principalId!),
        credentialSha256: productionCredentialDigest(profile),
        provisionedAt: new Date().toISOString(),
        syntheticNamespace: "routecairn-fixture-20261021"
      }))
    });
    const pair = { accountA: profiles[1]!, accountB: profiles[2]! };
    expect(() => assertProductionCampaignProfiles(campaign, profiles[0], pair)).not.toThrow();
    expect(() => assertProductionCampaignProfiles(campaign, profiles[1], pair)).toThrow("EXACT_FRESH_IDENTITY");
    expect(() =>
      assertProductionCampaignProfiles(campaign, profiles[0], { accountA: profiles[2]!, accountB: profiles[1]! })
    ).toThrow("EXACT_FRESH_IDENTITY");
    for (const patch of [
      { role: "admin" },
      { headers: { authorization: "Bearer fixture-only-replacement" } },
      { principalId: "foreign" },
      { identityModel: model === "TENANT_AWARE" ? "PRINCIPAL_ROLE" : "TENANT_AWARE" }
    ])
      expect(() =>
        assertProductionCampaignProfiles(campaign, { ...profiles[0]!, ...patch } as (typeof profiles)[0], pair)
      ).toThrow("EXACT_FRESH_IDENTITY");
    expect(() => assertProductionCampaignProfiles(campaign, profiles[0], undefined)).toThrow("EXACT_FRESH_IDENTITY");
    expect(
      productionCampaignSchema.safeParse({
        ...campaign,
        identities: campaign.identities.map((i) => ({ ...i, provisionedAt: "2020-01-01T00:00:00.000Z" }))
      }).success
    ).toBe(false);
    expect(() => assertProductionCampaignProfiles(p, profiles[0], pair)).toThrow("CREDENTIALS_PROHIBITED");
  }
);
