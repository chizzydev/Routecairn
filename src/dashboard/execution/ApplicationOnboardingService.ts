import { applicationOnboardingSchema } from "../contracts/ApplicationOnboardingContracts.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { TargetRepository } from "../db/DashboardRepositories.js";
import { exampleScope } from "../../config/defaults.js";
import { observeLinks } from "../../modules/apiGraphql/ObservedLinks.js";
import type { ApplicationMappingInput } from "../contracts/ApplicationMappingContracts.js";
/** Saves declarations atomically. Identity is verified only by separately approved native observations. */
export class ApplicationOnboardingService {
  constructor(
    private readonly db: DashboardDatabase,
    private readonly vault: CredentialVault
  ) {}
  public create(org: string, value: unknown, actor: string) {
    const v = applicationOnboardingSchema.parse(value);
    for (const p of [v.identityPath, v.seedPath])
      if (
        !observeLinks(JSON.stringify({ href: p }), v.origin + "/", "application/json", true).candidates.some(
          (c) => c.path === p
        )
      )
        throw Error("WORKBENCH_ONBOARDING_SAFE_GET_REQUIRED");
    return this.db.transaction(() => {
      const targetId = new TargetRepository(this.db).create({
        organizationId: org,
        createdBy: actor,
        displayName: v.displayName,
        baseOrigin: v.origin,
        tags: ["application-onboarding"],
        classification: "LOCAL",
        authorizationType: "OWNED",
        authorizationSummary: v.authorizationSummary,
        productionEnabled: false,
        approvedScope: {
          ...exampleScope,
          allowedDomains: ["127.0.0.1"],
          allowedMethods: ["GET"],
          sameOriginOnly: true,
          includeSubdomains: false,
          concurrency: 1,
          rateLimitPerSecond: 20
        }
      });
      const credentials = {} as ApplicationMappingInput["credentials"];
      for (const slot of ["primary", "account_a", "account_b"] as const) {
        const a = v.actors[slot];
        credentials[slot] = this.vault.create({
          organizationId: org,
          targetId,
          createdByUserId: actor,
          name: a.principal,
          safeAlias: a.principal,
          expiresAt: a.expiresAt,
          safeIdentitySummary: {
            ...(v.identityModel ? { identityModel: v.identityModel } : {}),
            principalId: a.principal,
            ...(a.tenant ? { tenantId: a.tenant } : {}),
            role: a.role
          },
          secret: {
            authorizationHeader: a.authorizationHeader,
            identityVerification: {
              endpoint: v.origin + v.identityPath,
              principalFieldPath: v.principalField,
              tenantFieldPath: v.tenantField,
              roleFieldPath: v.roleField
            }
          }
        });
      }
      return {
        targetId,
        credentials,
        executionAuthority: "NONE" as const,
        identityStatus: "DECLARED_NOT_VERIFIED" as const,
        requestsSent: 0,
        input: {
          ...(v.identityModel ? { identityModel: v.identityModel } : {}),
          targetId,
          credentials,
          identityContextConfirmed: true,
          readOnlyRoutesConfirmed: true,
          routes: [
            {
              id: "onboarded-seed",
              kind: "OBJECT" as const,
              method: "GET" as const,
              url: v.origin + v.seedPath,
              pathTemplate: v.seedPath,
              identityPath: v.objectField,
              tenantPath: v.objectTenantField
            }
          ]
        } satisfies ApplicationMappingInput
      };
    });
  }
}
