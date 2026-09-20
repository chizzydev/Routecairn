import { z } from "zod";
import { scanProfileNameSchema } from "../../config/ScanProfiles.js";
import { authorizationWorkflowConfigurationsSchema } from "./ScanStudioSchemas.js";
import { advancedEngineIds } from "./AdvancedEngineSchemas.js";

export const liveAcceptanceLaneKindSchema = z.enum([
  "PUBLIC_BASELINE",
  "AUTHENTICATED_IDENTITY",
  "ACCOUNT_PAIR_AUTHORIZATION",
  "BROWSER_LEARNING",
  "AUTHENTICATION_LIFECYCLE",
  "API_GRAPHQL_AUTHORIZATION",
  "DATA_AUTHORIZATION",
  "BUSINESS_LOGIC",
  "OPERATIONAL_ENDPOINTS",
  "BILLING_ENTITLEMENTS",
  "MUTATION_ACCEPTANCE",
  "RECOVERY_ACCEPTANCE",
  "MULTI_TENANT_APPLICATION",
  "SUPABASE_RLS_STORAGE_RPC",
  "OAUTH_MFA_PASSKEYS",
  "GRAPHQL_AUTHORIZATION",
  "SIGNED_PORTALS_EXPORTS",
  "SYNTHETIC_PAYMENT_PROVIDER",
  "WEBHOOKS_CRON",
  "REMEDIATION_RERUNS",
  "CUSTOM"
]);

export const broaderRealTargetLaneKinds = [
  "MULTI_TENANT_APPLICATION",
  "SUPABASE_RLS_STORAGE_RPC",
  "OAUTH_MFA_PASSKEYS",
  "GRAPHQL_AUTHORIZATION",
  "SIGNED_PORTALS_EXPORTS",
  "SYNTHETIC_PAYMENT_PROVIDER",
  "WEBHOOKS_CRON",
  "REMEDIATION_RERUNS"
] as const;

export const liveAcceptanceFeatureSchema = z.enum([
  "MULTI_TENANT_AUTHORIZATION",
  "SUPABASE_TABLE_RLS",
  "SUPABASE_STORAGE",
  "SUPABASE_RPC",
  "OAUTH_OIDC",
  "MFA",
  "PASSKEY",
  "GRAPHQL_AUTHORIZATION",
  "SIGNED_LINK",
  "SIGNED_PORTAL",
  "PROTECTED_EXPORT",
  "SYNTHETIC_PAYMENT",
  "WEBHOOK",
  "CRON",
  "REMEDIATION_COMPARISON"
]);

const identifierSchema = z.string().regex(/^[A-Za-z0-9._-]+$/).max(120);
const reasonSchema = z.string().min(12).max(1000);
const advancedEngineSchema = z.object({ engineId: z.enum(advancedEngineIds), value: z.unknown() }).strict();

const executableLaneSchema = z.object({
  disposition: z.literal("EXECUTE_SCAN"),
  profile: scanProfileNameSchema,
  authentication: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("public") }).strict(),
    z.object({ mode: z.literal("primary"), credentialProfileId: z.string().uuid() }).strict(),
    z.object({ mode: z.literal("account-pair"), accountAProfileId: z.string().uuid(), accountBProfileId: z.string().uuid() }).strict()
  ]),
  includeModules: z.array(z.string().min(1).max(120)).max(40).default([]),
  workflows: authorizationWorkflowConfigurationsSchema.default([]),
  advancedEngines: z.array(advancedEngineSchema).max(12).default([]),
  maxRequests: z.number().int().min(1).max(10000).default(250),
  cleanupReservedRequests: z.number().int().min(0).max(5000).default(0),
  rateLimitPerSecond: z.number().positive().max(50).default(3),
  concurrency: z.number().int().min(1).max(50).default(3),
  evidenceLevel: z.enum(["minimal", "normal", "strong"]).default("strong")
}).strict();

const linkedLaneSchema = z.object({ disposition: z.literal("LINK_SCAN"), scanId: z.string().uuid() }).strict();
const notApplicableLaneSchema = z.object({ disposition: z.literal("NOT_APPLICABLE"), reason: reasonSchema, evidenceScanId: z.string().uuid().optional() }).strict();
const notAssessedLaneSchema = z.object({ disposition: z.literal("NOT_ASSESSED"), reason: reasonSchema }).strict();
const remediationLaneSchema = z.object({
  disposition: z.literal("LINK_REMEDIATION"),
  baselineScanId: z.string().uuid(),
  rerunScanId: z.string().uuid(),
  comparisonId: z.string().uuid()
}).strict();

export const liveAcceptanceProofContractSchema = z.object({
  requiredModules: z.array(identifierSchema).max(40).default([]),
  requiredWorkflows: z.array(identifierSchema).max(40).default([]),
  requiredFeatures: z.array(liveAcceptanceFeatureSchema).max(30).default([]),
  minimumCompletedCases: z.number().int().min(0).max(10000).default(0),
  minimumTransmittedCases: z.number().int().min(0).max(10000).default(0),
  requireStrongEvidence: z.boolean().default(true),
  requireProviderAdapter: z.boolean().default(false),
  requireResolvedCleanup: z.boolean().default(true),
  requireComparableRemediation: z.boolean().default(false),
  requireNoUnretestedCases: z.boolean().default(false)
}).strict();

export const liveAcceptanceLaneSchema = z.object({
  id: identifierSchema,
  label: z.string().min(3).max(160),
  kind: liveAcceptanceLaneKindSchema,
  required: z.boolean().default(true),
  proof: liveAcceptanceProofContractSchema.default({}),
  execution: z.discriminatedUnion("disposition", [executableLaneSchema, linkedLaneSchema, remediationLaneSchema, notApplicableLaneSchema, notAssessedLaneSchema])
}).strict().superRefine((value, ctx) => {
  if (value.execution.disposition === "EXECUTE_SCAN") {
    if (value.execution.cleanupReservedRequests > value.execution.maxRequests) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "cleanupReservedRequests"], message: "Cleanup reserve cannot exceed the lane request budget." });
    if (value.execution.authentication.mode === "account-pair" && value.execution.authentication.accountAProfileId === value.execution.authentication.accountBProfileId) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "authentication", "accountBProfileId"], message: "Account A and Account B must be different credential profiles." });
    if (new Set(value.execution.advancedEngines.map((item) => item.engineId)).size !== value.execution.advancedEngines.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "advancedEngines"], message: "An advanced engine may appear only once per lane." });
  }
  if (["MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE"].includes(value.kind) && value.execution.disposition === "EXECUTE_SCAN") {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "disposition"], message: "Mutation and recovery acceptance must link a separately approved controlled-mutation scan." });
  }
  if (value.kind === "REMEDIATION_RERUNS" && !["LINK_REMEDIATION", "NOT_ASSESSED", "NOT_APPLICABLE"].includes(value.execution.disposition)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "disposition"], message: "Remediation acceptance must link an exact baseline, rerun, and persisted comparison." });
  }
  if (value.execution.disposition === "LINK_REMEDIATION" && value.kind !== "REMEDIATION_RERUNS") {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "disposition"], message: "LINK_REMEDIATION is reserved for the remediation-rerun lane." });
  }
  if (value.execution.disposition === "LINK_REMEDIATION" && value.execution.baselineScanId === value.execution.rerunScanId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["execution", "rerunScanId"], message: "The remediation rerun must be a different scan from its baseline." });
  }
});

export const liveAcceptancePlanInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  standard: z.enum(["CUSTOM", "BROADER_REAL_TARGET_V1"]).default("CUSTOM"),
  name: z.string().min(3).max(160),
  targetId: z.string().uuid(),
  environment: z.enum(["STAGING", "PRODUCTION"]),
  authorization: z.object({
    mode: z.enum(["OWNED_PRODUCTION", "INTERNAL_STAGING", "BUG_BOUNTY_AUTHORIZED"]),
    proofReference: z.string().min(3).max(240),
    proofSha256: z.string().regex(/^[a-f0-9]{64}$/),
    authorizedBy: z.string().min(2).max(160),
    startsAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    neverTestPaths: z.array(z.string().min(1).max(1000).regex(/^\//)).max(100).default([]),
    authenticationPermitted: z.boolean(),
    mutationPermitted: z.boolean(),
    disposableAccountsOnly: z.literal(true),
    realPaymentsAllowed: z.literal(false),
    destructiveAdministrationAllowed: z.literal(false)
  }).strict(),
  lanes: z.array(liveAcceptanceLaneSchema).min(1).max(24)
}).strict().superRefine((value, ctx) => {
  if (Date.parse(value.authorization.startsAt) >= Date.parse(value.authorization.expiresAt)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authorization", "expiresAt"], message: "Authorization expiry must be after its start time." });
  if (value.environment === "PRODUCTION" && value.authorization.mode !== "OWNED_PRODUCTION" && value.authorization.mode !== "BUG_BOUNTY_AUTHORIZED") ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authorization", "mode"], message: "Production acceptance requires owned-production or bug-bounty authorization." });
  if (new Set(value.lanes.map((lane) => lane.id)).size !== value.lanes.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes"], message: "Lane IDs must be unique." });
  if (value.standard === "BROADER_REAL_TARGET_V1") {
    if (value.environment !== "PRODUCTION") ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["environment"], message: "Broader real-target acceptance requires a production-classified target." });
    for (const kind of broaderRealTargetLaneKinds) {
      const matches = value.lanes.filter((lane) => lane.kind === kind);
      if (matches.length !== 1) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes"], message: `Broader real-target acceptance requires exactly one ${kind} lane.` });
      else if (!matches[0]!.required) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", value.lanes.indexOf(matches[0]!), "required"], message: `${kind} must be required by this acceptance standard.` });
    }
  }
  for (const [index, lane] of value.lanes.entries()) {
    if (lane.execution.disposition === "EXECUTE_SCAN" && lane.execution.authentication.mode !== "public" && !value.authorization.authenticationPermitted) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", index, "execution", "authentication"], message: "Authenticated lanes require authentication permission." });
    if (["MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE"].includes(lane.kind) && !value.authorization.mutationPermitted && lane.execution.disposition === "LINK_SCAN") ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", index], message: "Mutation and recovery evidence requires mutation permission in the acceptance authorization." });
  }
});

export const liveAcceptanceReviewSchema = z.object({ planDigest: z.string().regex(/^[a-f0-9]{64}$/), confirmation: z.literal("I_CONFIRM_REVIEWED_LIVE_ACCEPTANCE_PLAN") }).strict();
export const liveAcceptanceExecuteSchema = z.object({ planDigest: z.string().regex(/^[a-f0-9]{64}$/), confirmation: z.literal("I_CONFIRM_EXECUTE_REVIEWED_LIVE_ACCEPTANCE_PLAN") }).strict();

export type LiveAcceptancePlanInput = z.infer<typeof liveAcceptancePlanInputSchema>;
export type LiveAcceptanceLane = z.infer<typeof liveAcceptanceLaneSchema>;
