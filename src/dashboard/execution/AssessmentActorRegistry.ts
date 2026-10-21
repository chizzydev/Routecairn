import { createHash } from "node:crypto";
import { targetAuthorizationSchema } from "../../core/authorization/TargetAuthorization.js";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import {
  actorRegistrySchema,
  actorRegistryDigest,
  credentialDigest,
  identityFingerprint,
  actorIdSchema,
  validateActorRegistry
} from "../../core/auth/ActorRegistry.js";
import { assessCapabilities } from "../../core/auth/AssessmentCapabilities.js";
import { authProfileSchema } from "../../core/auth/AuthProfile.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { authProfileFromCredential } from "./ScanExecutionShared.js";
import { assessmentResourcePolicySchema, compileAssessmentResources } from "./AssessmentResourcePolicy.js";
import { TargetRepository } from "../db/DashboardRepositories.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
export const assessmentActorInputSchema = z
  .object({
    targetId: z.string().uuid(),
    resources: z.array(assessmentResourcePolicySchema).max(4).default([]),
    readPath: z
      .string()
      .regex(/^\/[A-Za-z0-9_./-]*$/)
      .max(300),
    actors: z
      .array(
        z
          .object({
            id: actorIdSchema,
            label: z.string().min(1).max(80),
            credentialProfileId: z.string().uuid(),
            mechanism: z.enum(["BEARER", "COOKIE", "API_KEY", "BROWSER_SESSION"]),
            accountProvenance: z.enum(["FRESH_DISPOSABLE", "OWNER_APPROVED_EXISTING_TEST"])
          })
          .strict()
      )
      .max(8),
    credentialValidUntil: z.string().datetime(),
    ownerTestAccountsConfirmed: z.literal(true),
    readOnlyEffectConfirmed: z.literal(true),
    sessionHousekeepingApproved: z.boolean(),
    roleSeparationApplicable: z.boolean().default(false),
    tenantSeparationApplicable: z.boolean().default(false)
  })
  .strict();
export function prepareAssessmentActors(db: DashboardDatabase, vault: CredentialVault, org: string, value: unknown) {
  const input = assessmentActorInputSchema.parse(value),
    target = new TargetRepository(db).get(input.targetId, true, org);
  if (!target || target.organizationId !== org) throw Error("ASSESSMENT_TARGET_CONTEXT_REQUIRED");
  const url = new URL(input.readPath, target.baseOrigin),
    scope = scopeSchema.parse(target.approvedScope);
  if (
    url.origin !== target.baseOrigin ||
    url.search ||
    url.hash ||
    url.pathname !== input.readPath ||
    !new ScopeMatcher(target.baseOrigin, scope).decide(url.href, "GET").allowed
  )
    throw Error("ASSESSMENT_EXACT_APPROVED_READ_PATH_REQUIRED");
  if (input.actors.length && !input.sessionHousekeepingApproved) throw Error("SESSION_HOUSEKEEPING_APPROVAL_REQUIRED");
  if (
    Date.parse(input.credentialValidUntil) <= Date.now() ||
    Date.parse(input.credentialValidUntil) > Date.now() + 86400000
  )
    throw Error("CREDENTIAL_VALIDITY_WINDOW_REQUIRED");
  const registryId = randomUUID(),
    bindingKey = input.actors.length ? vault.actorBindingKey(org, target.id, registryId) : undefined;
  const identityPaths = new Set<string>();
  const validationProfiles: Record<string, import("../../core/auth/AuthProfile.js").AuthProfile> = Object.create(null);
  const actors = input.actors.map((a) => {
    const summary = vault.getSummary(a.credentialProfileId, org);
    if (!summary || summary.organizationId !== org || summary.targetId !== target.id)
      throw Error("ASSESSMENT_CREDENTIAL_CONTEXT_REQUIRED");
    const availability = !summary.enabled
      ? "REVOKED"
      : Date.parse(summary.expiresAt ?? input.credentialValidUntil) <= Date.now()
        ? "EXPIRED"
        : "AVAILABLE";
    const p =
      availability === "AVAILABLE"
        ? authProfileSchema.parse(authProfileFromCredential(summary, vault.decryptForHealthCheck(summary.id)))
        : undefined;
    if (p) validationProfiles[a.id] = p;
    if (p?.identityVerification.endpoint) {
      const u = new URL(p.identityVerification.endpoint, target.baseOrigin);
      if (
        u.origin !== target.baseOrigin ||
        u.search ||
        u.hash ||
        !new ScopeMatcher(target.baseOrigin, scope).decide(u.href, "GET").allowed
      )
        throw Error("ASSESSMENT_IDENTITY_SCOPE_REQUIRED");
      identityPaths.add(u.pathname);
    }
    const principal = p?.principalId ?? summary.safeIdentitySummary.principalId,
      role = p?.role ?? summary.safeIdentitySummary.role,
      tenant = p?.tenantId ?? summary.safeIdentitySummary.tenantId;
    return {
      id: a.id,
      label: a.label,
      authentication: {
        mechanism: a.mechanism,
        availability,
        credentialRef: summary.id,
        ...(p ? { credentialDigest: credentialDigest(p, bindingKey) } : {}),
        credentialExpiresAt: new Date(
          Math.min(Date.parse(summary.expiresAt ?? input.credentialValidUntil), Date.parse(input.credentialValidUntil))
        ).toISOString(),
        accountProvenance: a.accountProvenance,
        suitableForTesting: true
      },
      ...(typeof principal === "string" ? { principalFingerprint: identityFingerprint(principal) } : {}),
      ...(typeof role === "string" ? { roleFingerprint: identityFingerprint(role) } : {}),
      ...(typeof tenant === "string" ? { tenantFingerprint: identityFingerprint(tenant) } : {})
    };
  });
  const ids = actors.map((a) => a.id),
    workflows = [
      { id: "public", family: "PUBLIC_OBSERVATION", actorIds: [], reviewed: true },
      ...ids.map((id) => ({
        id: "observe-" + id,
        family: "AUTHENTICATED_OBSERVATION",
        actorIds: [id],
        reviewed: true
      })),
      { id: "ownership", family: "OWNERSHIP_COMPARISON", actorIds: ids, reviewed: true },
      {
        id: "roles",
        family: "ROLE_COMPARISON",
        actorIds: ids,
        reviewed: true,
        applicable: input.roleSeparationApplicable
      },
      {
        id: "tenants",
        family: "TENANT_COMPARISON",
        actorIds: ids,
        reviewed: true,
        applicable: input.tenantSeparationApplicable
      }
    ];
  const resourcePlan = compileAssessmentResources(
    input.resources,
    actors as import("../../core/auth/ActorRegistry.js").ActorRegistry["actors"],
    target.baseOrigin,
    scope
  );
  const registry = actorRegistrySchema.parse({
      contractVersion: 2,
      registryId,
      organizationId: org,
      targetOrigin: target.baseOrigin,
      actors,
      workflows: [...workflows, ...resourcePlan.workflows]
    }),
    actorCredentials = Object.fromEntries(input.actors.map((a) => [a.id, a.credentialProfileId]));
  validateActorRegistry(registry, validationProfiles, target.baseOrigin, org, bindingKey);
  const apiGraphql = {
    actors: [
      { id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" },
      ...actors.map((a) => ({
        id: a.id,
        safeAlias: a.label,
        authSlot: "registry",
        relationship: "OWNER_REVIEWED_TEST_ACTOR"
      }))
    ],
    routes: [
      {
        id: "reviewed-read",
        safeAlias: "Reviewed read",
        protocol: "REST",
        kind: "FUNCTION",
        functionName: "reviewed-read",
        url: url.href,
        documentedMethods: ["GET"]
      }
    ],
    checks: [
      {
        id: "public-read",
        matrixId: "public",
        label: "Reviewed public HTTP observation",
        kind: "FUNCTION_AUTHORIZATION",
        routeId: "reviewed-read",
        actorId: "public",
        requireVerifiedIdentity: false,
        request: { method: "GET" },
        response: { expectedDecision: "OBSERVE" }
      },
      ...actors.map((a) => ({
        id: "read-" + a.id,
        matrixId: "observe-" + a.id,
        label: "Reviewed credential-bound observation",
        kind: "FUNCTION_AUTHORIZATION",
        routeId: "reviewed-read",
        actorId: a.id,
        requireVerifiedIdentity: false,
        request: { method: "GET" },
        response: { expectedDecision: "OBSERVE" }
      }))
    ]
  };
  apiGraphql.routes.push(...(resourcePlan.routes as typeof apiGraphql.routes));
  apiGraphql.checks.push(...(resourcePlan.checks as typeof apiGraphql.checks));
  const now = Date.now();
  const targetAuthorization = targetAuthorizationSchema.parse({
    schemaVersion: 1,
    mode: target.classification === "LOCAL" ? "INTERNAL_STAGING" : "OWNED_PRODUCTION",
    targetOrigin: target.baseOrigin,
    proof: {
      reference: target.authorizationSummary,
      sha256: createHash("sha256")
        .update(JSON.stringify([target.id, target.rowVersion, target.authorizationSummary]))
        .digest("hex")
    },
    productionCampaign: {
      contractVersion: 2,
      campaignId: randomUUID(),
      program: "Reviewed flexible application assessment",
      platform: "OWNER_CONTROLLED",
      reportMode: "PRODUCTION_READ_ONLY",
      startsAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(),
      budgetScope: "PER_ASSESSMENT_RUN",
      maxRequests: 60,
      rateLimitPerSecond: Math.min(3, scope.rateLimitPerSecond),
      concurrency: 1,
      requestTimeoutMs: 10000,
      maxDurationMs: 120000,
      maxResponseBytes: 16384,
      inScope: [{ origin: target.baseOrigin, pathPrefix: "/" }],
      outOfScope: scope.disallowedPaths.map((pathPrefix) => ({ origin: target.baseOrigin, pathPrefix })),
      rules: ["Exact reviewed GET requests only; candidates never become authority"],
      prohibitedActions: [
        "No customer data, provisioning, payment, mail, third-party providers or state-changing operations"
      ],
      requests: [...new Set(["/", input.readPath, ...identityPaths, ...resourcePlan.paths])].map((path) => ({
        origin: target.baseOrigin,
        path,
        method: "GET",
        effect: "READ",
        expectedStatuses: [200, 401, 403]
      })),
      staticAssets: [],
      workflows: [actors.length ? "AUTHENTICATED_READ_ONLY" : "PUBLIC_READ_ONLY"],
      authenticationPermitted: actors.length > 0,
      mutationPermitted: false,
      destructivePermitted: false,
      racePermitted: false,
      effects: {
        sessionHousekeeping: actors.length ? "SESSION_LAST_USED_AT_UPDATE" : "NONE_PUBLIC_UNAUTHENTICATED",
        approved: true
      },
      retention: {
        retainEvidence: true,
        rawBodiesInPortableReport: false,
        cleanup: "RETAIN_EVIDENCE_NO_AUTOMATIC_DELETION",
        stateChangingTests: "SEPARATE_REVERSIBLE_CONTRACT_REQUIRED"
      },
      actorRegistryDigest: actorRegistryDigest(registry),
      actorIds: registry.actors.map((a) => a.id),
      workflowAuthorizations: registry.workflows
    }
  });
  return {
    contractVersion: 2,
    registry,
    targetAuthorization,
    actorCredentials,
    apiGraphql,
    resourcePolicies: input.resources,
    resourceAdapterVersion: resourcePlan.adapterVersion,
    digest: actorRegistryDigest(registry),
    capabilities: assessCapabilities(registry),
    executionAuthority: "NONE_PREVIEW_ONLY",
    requestsSent: 0,
    manualReview:
      "No login/principal/role/tenant or resource ownership is inferred from supplied credentials. Review native observations and approved business policies separately."
  };
}
