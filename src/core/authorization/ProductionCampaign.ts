import {
  workflowAuthorizationSchema,
  actorWorkflowDigest,
  actorRegistryDigest,
  type ActorRegistry,
  type ActorProfiles,
  validateActorRegistry
} from "../auth/ActorRegistry.js";
import { z } from "zod";
import { createHash } from "node:crypto";
import type { AuthProfile } from "../auth/AuthProfile.js";
import type { AuthProfileSet } from "../auth/AuthProfileSet.js";
const origin = z
  .string()
  .url()
  .refine((v) => {
    const u = new URL(v);
    return ["https:", "http:"].includes(u.protocol) && u.origin === v;
  }, "Exact origin required");
const path = z
  .string()
  .min(1)
  .max(1000)
  .refine(
    (v) =>
      v.startsWith("/") &&
      !/[?#%\\;]/.test(v) &&
      !v.includes("//") &&
      !v.split("/").some((p) => p === "." || p === ".."),
    "Canonical path required"
  );
const asset = z.object({ origin, pathPrefix: path }).strict();
const fp = z.string().regex(/^[a-f0-9]{64}$/);
export const legacyProductionCampaignSchema = z
  .object({
    campaignId: z.string().uuid(),
    program: z.string().min(3).max(160),
    platform: z.literal("OWNER_CONTROLLED"),
    reportMode: z.literal("PRODUCTION_READ_ONLY"),
    startsAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    budgetScope: z.literal("PER_ASSESSMENT_RUN"),
    maxRequests: z.number().int().min(1).max(300),
    rateLimitPerSecond: z.number().int().min(1).max(3),
    concurrency: z.number().int().min(1).max(2),
    requestTimeoutMs: z.number().int().min(1000).max(30000),
    maxDurationMs: z.number().int().min(1000).max(600000),
    maxResponseBytes: z
      .number()
      .int()
      .min(512)
      .max(1024 * 1024),
    inScope: z.array(asset).min(1).max(8),
    outOfScope: z.array(asset).max(100),
    rules: z.array(z.string().min(3).max(240)).min(1).max(30),
    prohibitedActions: z.array(z.string().min(3).max(240)).min(1).max(30),
    requests: z
      .array(
        z
          .object({
            origin,
            path,
            method: z.enum(["GET", "HEAD", "OPTIONS"]),
            effect: z.literal("READ"),
            bodySha256: z.never().optional(),
            expectedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(10)
          })
          .strict()
      )
      .min(1)
      .max(100),
    staticAssets: z
      .array(
        z
          .object({
            origin,
            pathPrefix: path.refine((v) => v.length > 2 && v.endsWith("/"), "Explicit asset directory required"),
            extensions: z
              .array(z.enum([".js", ".css", ".woff2", ".woff", ".png", ".svg", ".ico", ".webp"]))
              .min(1)
              .max(8)
          })
          .strict()
      )
      .max(8),
    workflows: z
      .array(z.enum(["PUBLIC_DISCOVERY", "PUBLIC_READ_ONLY", "AUTHENTICATED_READ_ONLY"]))
      .min(1)
      .max(3),
    authenticationPermitted: z.boolean(),
    mutationPermitted: z.literal(false),
    destructivePermitted: z.literal(false),
    racePermitted: z.literal(false),
    disposableAccountsSupplied: z.boolean(),
    identities: z
      .array(
        z
          .object({
            slot: z.enum(["primary", "account_a", "account_b"]),
            identityModel: z.enum(["TENANT_AWARE", "PRINCIPAL_ROLE"]),
            principalFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
            credentialSha256: fp,
            provisionedAt: z.string().datetime(),
            syntheticNamespace: z.string().regex(/^routecairn-[a-z0-9-]{8,80}$/)
          })
          .strict()
      )
      .max(3),
    effects: z
      .object({
        sessionHousekeeping: z.enum(["NONE_PUBLIC_UNAUTHENTICATED", "SESSION_LAST_USED_AT_UPDATE"]),
        approved: z.literal(true)
      })
      .strict(),
    retention: z
      .object({
        retainEvidence: z.literal(true),
        rawBodiesInPortableReport: z.literal(false),
        cleanup: z.literal("RETAIN_EVIDENCE_NO_AUTOMATIC_DELETION"),
        stateChangingTests: z.literal("SEPARATE_REVERSIBLE_CONTRACT_REQUIRED")
      })
      .strict()
  })
  .strict()
  .superRefine((v, c) => {
    const fail = (message: string) => c.addIssue({ code: z.ZodIssueCode.custom, message });
    if (Date.parse(v.startsAt) >= Date.parse(v.expiresAt)) fail("Invalid campaign window");
    if (new Set(v.requests.map((r) => r.origin + r.path + ":" + r.method)).size !== v.requests.length)
      fail("Duplicate campaign requests");
    for (const r of [...v.requests, ...v.staticAssets.map((a) => ({ ...a, path: a.pathPrefix }))])
      if (
        !v.inScope.some((a) => productionAssetMatches(new URL(r.origin + r.path), a)) ||
        v.outOfScope.some((a) => productionAssetMatches(new URL(r.origin + r.path), a))
      )
        fail("Campaign request outside declared scope");
    if (v.authenticationPermitted) {
      if (
        !v.disposableAccountsSupplied ||
        v.identities.length !== 3 ||
        new Set(v.identities.map((i) => i.slot)).size !== 3 ||
        new Set(v.identities.map((i) => i.principalFingerprint)).size !== 3 ||
        !v.workflows.includes("AUTHENTICATED_READ_ONLY") ||
        v.effects.sessionHousekeeping !== "SESSION_LAST_USED_AT_UPDATE" ||
        v.staticAssets.length
      )
        fail(
          "Authenticated campaign requires three fresh bound identities, reviewed session effects and no shared asset credential forwarding"
        );
      if (
        v.identities.some(
          (i) =>
            Date.parse(i.provisionedAt) < Date.parse(v.startsAt) ||
            Date.parse(i.provisionedAt) >= Date.parse(v.expiresAt)
        )
      )
        fail("New identities must be provisioned within this campaign window");
    } else if (
      v.identities.length ||
      v.disposableAccountsSupplied ||
      v.workflows.includes("AUTHENTICATED_READ_ONLY") ||
      v.effects.sessionHousekeeping !== "NONE_PUBLIC_UNAUTHENTICATED"
    )
      fail("Public campaign cannot adopt identities or session effects");
  });
const productionCampaignV2Schema = legacyProductionCampaignSchema
  .innerType()
  .omit({ identities: true, disposableAccountsSupplied: true })
  .extend({
    contractVersion: z.literal(2),
    actorRegistryDigest: z.string().regex(/^[a-f0-9]{64}$/),
    actorIds: z.array(z.string().min(1).max(64)).max(8),
    workflowAuthorizations: z.array(workflowAuthorizationSchema).max(64)
  })
  .strict()
  .superRefine((v, c) => {
    const fail = (message: string) => c.addIssue({ code: z.ZodIssueCode.custom, message });
    if (Date.parse(v.startsAt) >= Date.parse(v.expiresAt)) fail("Invalid campaign window");
    if (new Set(v.requests.map((r) => r.origin + r.path + ":" + r.method)).size !== v.requests.length)
      fail("Duplicate campaign requests");
    if (new Set(v.workflowAuthorizations.map((w) => w.id)).size !== v.workflowAuthorizations.length)
      fail("Duplicate campaign workflows");
    if (v.authenticationPermitted && !v.workflows.includes("AUTHENTICATED_READ_ONLY"))
      fail("Authenticated workflow declaration required");
    if (
      !v.authenticationPermitted &&
      (v.workflows.includes("AUTHENTICATED_READ_ONLY") ||
        v.effects.sessionHousekeeping !== "NONE_PUBLIC_UNAUTHENTICATED")
    )
      fail("Public campaign cannot adopt session effects");
    if (new Set(v.actorIds).size !== v.actorIds.length) fail("Duplicate actor ids");
    if (v.workflowAuthorizations.some((w) => w.actorIds.some((id) => !v.actorIds.includes(id))))
      fail("Workflow actor outside campaign");
    if (!v.authenticationPermitted && v.actorIds.length) fail("Public campaign cannot adopt credentials");
    if (
      v.authenticationPermitted &&
      (v.effects.sessionHousekeeping !== "SESSION_LAST_USED_AT_UPDATE" || v.staticAssets.length)
    )
      fail("Review session effects and prevent asset credential forwarding");
    for (const r of [...v.requests, ...v.staticAssets.map((a) => ({ ...a, path: a.pathPrefix }))])
      if (
        !v.inScope.some((a) => productionAssetMatches(new URL(r.origin + r.path), a)) ||
        v.outOfScope.some((a) => productionAssetMatches(new URL(r.origin + r.path), a))
      )
        fail("Request outside scope");
  });
export const productionCampaignSchema = z.union([legacyProductionCampaignSchema, productionCampaignV2Schema]);
export function assertProductionRegistry(
  c: ProductionCampaign,
  registry: ActorRegistry | undefined,
  profiles: ActorProfiles | undefined,
  organization: string | undefined,
  target: string,
  bindingKey?: string
) {
  if (!("contractVersion" in c)) {
    if (registry) throw Error("LEGACY_CAMPAIGN_REGISTRY_MIX_FORBIDDEN");
    return;
  }
  if (!registry || !profiles || !organization) throw Error("CAMPAIGN_ACTOR_REGISTRY_REQUIRED");
  validateActorRegistry(registry, profiles, target, organization, bindingKey);
  if (
    actorRegistryDigest(registry) !== c.actorRegistryDigest ||
    JSON.stringify(registry.actors.filter((a) => a.authentication.mechanism !== "ANONYMOUS").map((a) => a.id)) !==
      JSON.stringify(c.actorIds) ||
    actorWorkflowDigest(registry.workflows) !== actorWorkflowDigest(c.workflowAuthorizations)
  )
    throw Error("CAMPAIGN_REGISTRY_OR_WORKFLOW_CHANGED");
}
export type ProductionCampaign = z.infer<typeof productionCampaignSchema>;
export function productionAssetMatches(u: URL, a: { origin: string; pathPrefix: string }) {
  const p = a.pathPrefix.replace(/\/$/, "");
  return u.origin === a.origin && (!p || u.pathname === p || u.pathname.startsWith(p + "/"));
}
export function productionCampaignRequestAllowed(p: ProductionCampaign, u: URL, method: string) {
  if (u.search || u.hash) return false;
  if (p.requests.some((r) => r.origin === u.origin && r.path === u.pathname && r.method === method)) return true;
  return (
    method === "GET" &&
    p.staticAssets.some(
      (a) =>
        u.origin === a.origin && u.pathname.startsWith(a.pathPrefix) && a.extensions.some((e) => u.pathname.endsWith(e))
    )
  );
}
export function productionCredentialDigest(p: AuthProfile) {
  return createHash("sha256").update(JSON.stringify(p)).digest("hex");
}
export function assertProductionCampaignProfiles(
  c: ProductionCampaign,
  primary: AuthProfile | undefined,
  pair: AuthProfileSet | undefined
) {
  if ("contractVersion" in c) {
    if (primary || pair) throw Error("REGISTRY_CAMPAIGN_LEGACY_CREDENTIALS_FORBIDDEN");
    return;
  }
  if (!c.authenticationPermitted) {
    if (primary || pair) throw Error("PRODUCTION_CAMPAIGN_CREDENTIALS_PROHIBITED");
    return;
  }
  const profiles = { primary, account_a: pair?.accountA, account_b: pair?.accountB };
  for (const i of c.identities) {
    const p = profiles[i.slot],
      principal = p?.principalId
        ? createHash("sha256")
            .update("routecairn-identity-v1\0" + p.principalId)
            .digest("hex")
            .slice(0, 16)
        : undefined;
    if (
      !p ||
      p.identityModel !== i.identityModel ||
      p.identityVerification?.mode !== "required" ||
      principal !== i.principalFingerprint ||
      productionCredentialDigest(p) !== i.credentialSha256
    )
      throw Error("PRODUCTION_CAMPAIGN_EXACT_FRESH_IDENTITY_REQUIRED");
  }
}
