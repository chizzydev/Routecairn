import { z } from "zod";
import { advancedEngineIds } from "./AdvancedEngineSchemas.js";

export const providerAdapterKinds = [
  "GENERIC_HTTP",
  "SUPABASE",
  "STRIPE_TEST",
  "ADYEN_TEST",
  "BRAINTREE_SANDBOX",
  "PAYPAL_SANDBOX",
  "PADDLE_SANDBOX",
  "CUSTOM_SYNTHETIC"
] as const;

export const providerAdapterCapabilities = [
  "DATA_AUTHORIZATION",
  "AUTHENTICATION_LIFECYCLE",
  "BUSINESS_INVARIANT",
  "CONTROLLED_RACE",
  "API_GRAPHQL_AUTHORIZATION",
  "CAPABILITY_LINKS",
  "OPERATIONAL_ENDPOINTS",
  "SYNTHETIC_BILLING",
  "ASSISTED_REVIEW",
  "PRE_HANDOVER",
  "BUG_BOUNTY_SCOPE"
] as const;

const authenticationSchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("public") }).strict(),
  z.object({ mode: z.literal("primary"), credentialProfileId: z.string().uuid() }).strict(),
  z.object({ mode: z.literal("account-pair"), accountAProfileId: z.string().uuid(), accountBProfileId: z.string().uuid() }).strict()
]);

export const providerAdapterInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  name: z.string().min(3).max(160),
  description: z.string().max(2000).default(""),
  targetId: z.string().uuid(),
  environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]),
  provider: z.enum(providerAdapterKinds),
  engineId: z.enum(advancedEngineIds),
  capabilities: z.array(z.enum(providerAdapterCapabilities)).min(1).max(providerAdapterCapabilities.length),
  authentication: authenticationSchema,
  engineConfiguration: z.unknown(),
  fixture: z.object({
    disposableOnly: z.literal(true),
    realPaymentExecution: z.literal("FORBIDDEN"),
    allowedPathPrefixes: z.array(z.string().min(1).max(500).regex(/^\//)).min(1).max(50),
    cleanupRequired: z.boolean(),
    cleanupEvidenceRequired: z.boolean(),
    operatorNotes: z.string().max(2000).default("")
  }).strict(),
  limits: z.object({
    maxRequests: z.number().int().min(1).max(10_000),
    cleanupReservedRequests: z.number().int().min(0).max(5_000),
    rateLimitPerSecond: z.number().positive().max(50),
    concurrency: z.number().int().min(1).max(50),
    evidenceLevel: z.enum(["minimal", "normal", "strong"]).default("strong")
  }).strict(),
  recommendationId: z.string().uuid().optional()
}).strict().superRefine((value, ctx) => {
  if (new Set(value.capabilities).size !== value.capabilities.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["capabilities"], message: "Capabilities must be unique." });
  if (value.limits.cleanupReservedRequests > value.limits.maxRequests) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["limits", "cleanupReservedRequests"], message: "Cleanup reserve cannot exceed total requests." });
  if (value.fixture.cleanupRequired && value.limits.cleanupReservedRequests < 1) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["limits", "cleanupReservedRequests"], message: "Mutating fixtures must reserve at least one cleanup request." });
  if (value.fixture.cleanupRequired && !value.fixture.cleanupEvidenceRequired) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["fixture", "cleanupEvidenceRequired"], message: "Mutating fixtures require authoritative cleanup evidence." });
  if (new Set(value.fixture.allowedPathPrefixes).size !== value.fixture.allowedPathPrefixes.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["fixture", "allowedPathPrefixes"], message: "Fixture path prefixes must be unique." });
  value.fixture.allowedPathPrefixes.forEach((prefix,index) => { if (/[?#\\\r\n\0]/.test(prefix) || prefix.split("/").includes("..")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["fixture","allowedPathPrefixes",index], message: "Fixture path prefixes must be canonical URL paths without traversal, query, fragment, or control characters." }); });
  if (value.authentication.mode === "account-pair" && value.authentication.accountAProfileId === value.authentication.accountBProfileId) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authentication", "accountBProfileId"], message: "Account A and Account B must use different credential profiles." });
  if (value.provider !== "GENERIC_HTTP" && value.provider !== "CUSTOM_SYNTHETIC" && value.engineId !== "billing-entitlement-security" && value.provider !== "SUPABASE") ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["provider"], message: "Payment-provider adapters may only configure the synthetic billing engine." });
});

export const providerAdapterReviewSchema = z.object({
  versionId: z.string().uuid(),
  adapterDigest: z.string().regex(/^[a-f0-9]{64}$/),
  confirmation: z.literal("I_CONFIRM_REVIEWED_PROVIDER_ADAPTER")
}).strict();

export const providerAdapterStateSchema = z.object({
  enabled: z.boolean(),
  impactDigest: z.string().regex(/^[a-f0-9]{64}$/),
  confirmation: z.literal("I_CONFIRM_PROVIDER_ADAPTER_STATE_CHANGE")
}).strict();

export const providerAdapterBindingSchema = z.object({
  profileId: z.string().uuid(),
  versionId: z.string().uuid(),
  adapterDigest: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();

export type ProviderAdapterInput = z.infer<typeof providerAdapterInputSchema>;
export type ProviderAdapterBinding = z.infer<typeof providerAdapterBindingSchema>;
