import { z } from "zod";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { scanProfileNameSchema } from "../../config/ScanProfiles.js";
import { scanStudioSchema } from "./ScanStudioSchemas.js";
import { browserBootstrapSchema } from "../../core/auth/AuthProfile.js";
import { assistedReviewInputSchema } from "../../modules/assistedReview/AssistedReviewPlanner.js";
import { preHandoverInputSchema } from "../../modules/preHandover/PreHandoverPlanner.js";
import { targetAuthorizationSchema } from "../../core/authorization/TargetAuthorization.js";

export const dashboardScanCreateSchema = z.object({
  target: z.string().url(),
  recoveryScope: scopeSchema.optional(),
  workflowRecoveryDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  scopeFile: z.string().min(1).max(1000).optional(),
  profile: scanProfileNameSchema,
  projectId: z.string().uuid().optional(),
  targetId: z.string().uuid().optional(),
  authorizationDeclaration: z.string().min(1).max(1000).optional(),
  configFile: z.string().min(1).max(1000).optional(),
  authFile: z.string().min(1).max(1000).optional(),
  authAFile: z.string().min(1).max(1000).optional(),
  authBFile: z.string().min(1).max(1000).optional(),
  credentialProfileId: z.string().uuid().optional(),
  credentialProfileAId: z.string().uuid().optional(),
  credentialProfileBId: z.string().uuid().optional(),
  rateLimitPerSecond: z.number().positive().max(50).optional(),
  concurrency: z.number().int().positive().max(50).optional(),
  maxRequests: z.number().int().positive().max(10000).optional(),
  cleanupReservedRequests: z.number().int().min(0).max(5000).optional(),
  includeModules: z.array(z.string().min(1).max(120)).max(40).optional(),
  authenticationLifecycleFile: z.string().min(1).max(1000).optional(),
  authenticationLifecycleAutoFile: z.string().min(1).max(1000).optional(),
  businessInvariantFile: z.string().min(1).max(1000).optional(),
  controlledRaceFile: z.string().min(1).max(1000).optional(),
  apiGraphqlFile: z.string().min(1).max(1000).optional(),
  linkPortalSecurityFile: z.string().min(1).max(1000).optional(),
  operationalEndpointSecurityFile: z.string().min(1).max(1000).optional(),
  billingEntitlementFile: z.string().min(1).max(1000).optional(),
  assistedReviewFile: z.string().min(1).max(1000).optional(),
  preHandoverFile: z.string().min(1).max(1000).optional(),
  preHandover: preHandoverInputSchema.optional(),
  targetAuthorizationFile: z.string().min(1).max(1000).optional(),
  targetAuthorization: targetAuthorizationSchema.optional(),
  assistedReview: assistedReviewInputSchema.optional(),
  studio: scanStudioSchema.optional()
}).superRefine((value, ctx) => {
  if (value.maxRequests !== undefined && value.cleanupReservedRequests !== undefined && value.cleanupReservedRequests > value.maxRequests) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["cleanupReservedRequests"], message: "Cleanup reserve cannot exceed the total scan request budget." });
  }
  if (value.preHandover && value.preHandoverFile) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Use an inline pre-handover manifest or a file, not both." });
  if (value.targetAuthorization && value.targetAuthorizationFile) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Use inline target authorization or a file, not both." });
  if (value.assistedReview && value.assistedReviewFile) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["assistedReview"], message: "Use an inline review manifest or a review file, not both." });
  if (!value.scopeFile && !value.studio?.scope) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["scopeFile"], message: "Provide either an inline Scan Studio scope or a scope file." });
  }
  if (value.authenticationLifecycleFile && value.authenticationLifecycleAutoFile) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authenticationLifecycleAutoFile"], message: "Use either an explicit lifecycle manifest or browser-learned lifecycle automation, not both." });
  }
  if ((value.credentialProfileAId && !value.credentialProfileBId) || (!value.credentialProfileAId && value.credentialProfileBId)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["credentialProfileAId"], message: "Account-pair credential profiles require both Account A and Account B." });
  }
  if (value.credentialProfileId && (value.credentialProfileAId || value.credentialProfileBId)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["credentialProfileId"], message: "Use either a single credential profile or an account-pair credential profile set, not both." });
  }
  if ((value.authFile && value.credentialProfileId) || (value.authAFile && value.credentialProfileAId) || (value.authBFile && value.credentialProfileBId)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authFile"], message: "Use either auth files or saved credential profiles for each actor, not both." });
  }
  if (value.studio && value.studio.authentication.mode !== "public" && (value.authFile || value.authAFile || value.authBFile || value.credentialProfileId || value.credentialProfileAId || value.credentialProfileBId)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["studio", "authentication"], message: "Scan Studio authentication cannot be combined with legacy auth inputs." });
  }
});

export const reviewTransitionSchema = z.object({
  newStatus: z.enum(["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"]),
  reason: z.string().min(1).max(2000).optional(),
  note: z.string().min(1).max(4000).optional(),
  duplicateTargetFindingId: z.string().uuid().optional(),
  reviewerLabel: z.string().min(1).max(120).optional()
});

export const proofPackCreateSchema = z.object({
  title: z.string().min(1).max(160),
  description: z.string().max(2000).optional(),
  findingIds: z.array(z.string().uuid()).min(1).max(100)
});

export const compareRequestSchema = z.object({
  oldScanId: z.string().uuid(),
  newScanId: z.string().uuid(),
  recompute: z.boolean().optional()
}).strict().refine((value) => value.oldScanId !== value.newScanId, { message: "Choose two different scans." });

export const importReportSchema = z.object({
  reportPath: z.string().min(1).max(1000)
});

export const savedConfigurationSchema = z.object({
  name: z.string().min(1).max(160),
  description: z.string().max(2000).optional(),
  targetTemplate: z.string().max(1000).optional(),
  profile: scanProfileNameSchema,
  modules: z.array(z.string().min(1).max(120)).max(40).default([]),
  limits: z.record(z.unknown()).default({}),
  scopeSettings: z.record(z.unknown()).default({}),
  browserPolicySettings: z.record(z.unknown()).default({}),
  evidenceLevel: z.string().min(1).max(40).default("normal"),
  workflowRefs: z.record(z.unknown()).default({}),
  expectedVersion: z.number().int().positive().optional(),
  changeSummary: z.string().max(500).optional()
});

export const projectSchema = z.object({
  name: z.string().min(1).max(160),
  description: z.string().max(2000).optional(),
  tags: z.array(z.string().min(1).max(60)).max(20).default([]),
  defaultProfile: scanProfileNameSchema.optional(),
  defaultScope: z.record(z.unknown()).default({}),
  expectedVersion: z.number().int().positive().optional()
});

export const targetSchema = z.object({
  projectId: z.string().uuid().optional(),
  displayName: z.string().min(1).max(160),
  baseOrigin: z.string().url(),
  description: z.string().max(2000).optional(),
  tags: z.array(z.string().min(1).max(60)).max(20).default([]),
  classification: z.enum(["PUBLIC", "PRIVATE", "LOCAL", "PRODUCTION", "UNKNOWN"]).default("UNKNOWN"),
  authorizationType: z.enum(["OWNED", "CLIENT_AUTHORIZED", "BUG_BOUNTY", "CONTROLLED_LAB", "OTHER_AUTHORIZED"]),
  authorizationSummary: z.string().min(12).max(1000),
  approvedScope: z.record(z.unknown()).default({}),
  productionEnabled: z.boolean().default(false),
  defaultProfile: scanProfileNameSchema.optional(),
  defaultConfigurationId: z.string().uuid().optional(),
  defaultCredentialProfileId: z.string().uuid().optional(),
  defaultEvidenceLevel: z.enum(["minimal", "normal", "strong"]).optional(),
  defaultAuthTemplate: z.record(z.unknown()).default({}),
  expectedVersion: z.number().int().positive().optional()
});

export const loginSchema = z.object({
  login: z.string().min(1).max(320),
  password: z.string().min(1).max(256)
});

export const userCreateSchema = z.object({
  login: z.string().min(1).max(320),
  password: z.string().min(12).max(256),
  role: z.enum(["OWNER", "ANALYST", "VIEWER"])
});

export const userUpdateSchema = z.object({
  role: z.enum(["OWNER", "ANALYST", "VIEWER"]).optional(),
  enabled: z.boolean().optional(),
  password: z.string().min(12).max(256).optional()
});

export const dashboardSettingsUpdateSchema = z.object({
  values: z.object({
    defaultProfile: scanProfileNameSchema.optional(),
    defaultEvidenceLevel: z.enum(["minimal", "normal", "strong"]).optional(),
    defaultRateLimitPerSecond: z.number().positive().max(50).optional(),
    defaultConcurrency: z.number().int().positive().max(50).optional(),
    retentionDays: z.number().int().min(1).max(3650).optional(),
    queueCapacity: z.number().int().min(1).max(1000).optional()
  }).strict(),
  expectedVersions: z.record(z.number().int().positive()).default({})
});

const safeHeaderRecordSchema = z.record(z.string().min(1).max(80), z.string().max(4000)).default({});

export const credentialProfileSchema = z.object({
  name: z.string().min(1).max(160),
  description: z.string().max(2000).optional(),
  safeAlias: z.string().min(1).max(160),
  projectId: z.string().uuid().optional(),
  targetId: z.string().uuid().optional(),
  expiresAt: z.string().datetime().optional(),
  safeIdentitySummary: z.record(z.unknown()).default({}),
  secret: z.object({
    authorizationHeader: z.string().max(4000).optional(),
    cookies: safeHeaderRecordSchema.optional(),
    headers: safeHeaderRecordSchema.optional(),
    csrfToken: z.string().max(2000).optional(),
    tenantHeader: z.string().max(2000).optional(),
    sessionHeader: z.string().max(2000).optional(),
    identityVerification: z.object({
      endpoint: z.string().url(),
      principalFieldPath: z.string().max(200).optional(),
      tenantFieldPath: z.string().max(200).optional(),
      roleFieldPath: z.string().max(200).optional(),
      accountStateFieldPath: z.string().max(200).optional()
    }).optional(),
    browserBootstrap: browserBootstrapSchema.optional(),
    lifecycleSecrets: z.record(z.string().regex(/^[A-Za-z0-9._-]{1,100}$/), z.string().min(1).max(8192)).optional()
  })
});

export const credentialMetadataSchema = credentialProfileSchema.omit({ secret: true });
export const credentialSecretSchema = credentialProfileSchema.shape.secret;
