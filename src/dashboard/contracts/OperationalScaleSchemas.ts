import { z } from "zod";

const safeName = z.string().trim().min(1).max(160);
const envName = z.string().regex(/^[A-Z][A-Z0-9_]{1,126}$/);

export const organizationCreateSchema = z.object({
  name: safeName,
  slug: z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/)
}).strict();

export const organizationMemberSchema = z.object({
  userId: z.string().uuid(),
  role: z.enum(["OWNER", "ADMIN", "ANALYST", "VIEWER"])
}).strict();

const httpsUrl = z.string().url().refine((value) => new URL(value).protocol === "https:", "HTTPS is required.");

export const ssoProviderSchema = z.object({
  organizationId: z.string().uuid(),
  name: safeName,
  issuer: httpsUrl,
  authorizationEndpoint: httpsUrl,
  tokenEndpoint: httpsUrl,
  jwksUri: httpsUrl,
  clientId: z.string().min(1).max(500),
  clientSecretEnv: envName,
  scopes: z.array(z.string().regex(/^[a-zA-Z0-9:._/-]{1,100}$/)).min(1).max(20).default(["openid", "email", "profile"]),
  allowedDomains: z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9.-]+$/)).max(50).default([]),
  enabled: z.boolean().default(true)
}).strict().superRefine((value, ctx) => {
  const issuer = new URL(value.issuer);
  for (const [name, endpoint] of [["authorizationEndpoint", value.authorizationEndpoint], ["tokenEndpoint", value.tokenEndpoint], ["jwksUri", value.jwksUri]] as const) {
    if (new URL(endpoint).hostname !== issuer.hostname) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [name], message: "OIDC endpoints must share the issuer hostname." });
  }
  if (!value.scopes.includes("openid")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["scopes"], message: "OIDC scope must include openid." });
});

export const notificationChannelSchema = z.object({
  organizationId: z.string().uuid(),
  name: safeName,
  kind: z.enum(["WEBHOOK", "SLACK", "EMAIL", "GITHUB", "JIRA"]),
  endpoint: httpsUrl.optional(),
  secretEnv: envName.optional(),
  configuration: z.object({
    recipients: z.array(z.string().email()).max(50).optional(),
    sender: z.string().email().optional(),
    repository: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/).optional(),
    projectKey: z.string().regex(/^[A-Z][A-Z0-9_]{0,19}$/).optional(),
    labels: z.array(z.string().min(1).max(80)).max(20).optional(),
    minimumSeverity: z.enum(["INFO", "WARNING", "CRITICAL"]).optional()
  }).strict().default({}),
  enabled: z.boolean().default(true)
}).strict().superRefine((value, ctx) => {
  if (["WEBHOOK", "EMAIL", "GITHUB", "JIRA"].includes(value.kind) && !value.endpoint) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["endpoint"], message: "Endpoint is required for this channel." });
  if (["SLACK", "EMAIL", "GITHUB", "JIRA"].includes(value.kind) && !value.secretEnv) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["secretEnv"], message: "A secret environment-variable reference is required." });
  if (value.kind === "EMAIL" && (!value.configuration.recipients?.length || !value.configuration.sender)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["configuration"], message: "Email channels require sender and recipients." });
});

export const notificationEnqueueSchema = z.object({
  channelIds: z.array(z.string().uuid()).min(1).max(50),
  eventType: z.string().regex(/^[A-Z][A-Z0-9_]{1,100}$/),
  resourceType: z.string().regex(/^[A-Z][A-Z0-9_]{1,100}$/),
  resourceId: z.string().max(200).optional(),
  idempotencyKey: z.string().min(8).max(200),
  payload: z.object({
    title: z.string().min(1).max(200),
    summary: z.string().min(1).max(2000),
    severity: z.enum(["INFO", "WARNING", "CRITICAL"]),
    url: httpsUrl.optional(),
    fields: z.record(z.union([z.string().max(500), z.number(), z.boolean()])).optional()
  }).strict()
}).strict();

export const remoteEnrollmentSchema = z.object({ organizationId: z.string().uuid(), nameHint: safeName.optional(), expiresInMinutes: z.number().int().min(5).max(10080).default(60) }).strict();
export const remoteWorkerEnrollSchema = z.object({ token: z.string().min(32).max(300), name: safeName, publicKeyPem: z.string().min(100).max(4000), capabilities: z.array(z.string().regex(/^[a-z0-9][a-z0-9:._-]{0,99}$/)).min(1).max(100), labels: z.record(z.string().max(100)).default({}) }).strict();
export const remoteHeartbeatSchema = z.object({ status: z.enum(["ONLINE", "DRAINING"]), resources: z.object({ cpuPercent: z.number().min(0).max(100), memoryBytes: z.number().int().nonnegative(), activeJobs: z.number().int().min(0).max(100) }).strict() }).strict();
export const remoteJobSchema = z.object({ organizationId: z.string().uuid(), kind: z.enum(["SCAN", "EXPORT", "MODULE", "PING"]), payload: z.record(z.unknown()), requiredCapabilities: z.array(z.string().regex(/^[a-z0-9][a-z0-9:._-]{0,99}$/)).max(100).default([]), priority: z.number().int().min(-100).max(100).default(0), maxAttempts: z.number().int().min(1).max(10).default(3) }).strict();
export const remoteJobResultSchema = z.object({ leaseToken: z.string().min(32).max(300), status: z.enum(["COMPLETED", "FAILED"]), result: z.record(z.unknown()).optional(), error: z.string().max(1000).optional() }).strict().refine((value) => value.status !== "FAILED" || Boolean(value.error), { message: "Failed jobs require a safe error." });
export const remoteJobLeaseRenewSchema = z.object({ leaseToken: z.string().min(32).max(300) }).strict();

export const cloudSyncPeerSchema = z.object({ organizationId: z.string().uuid(), name: safeName, endpoint: httpsUrl, sharedSecretEnv: envName, enabled: z.boolean().default(true) }).strict();
export const cloudSyncPushSchema = z.object({ organizationId: z.string().uuid(), cursor: z.number().int().nonnegative(), events: z.array(z.object({ eventId: z.string().uuid(), entityType: z.string().max(100), entityId: z.string().max(200), operation: z.enum(["UPSERT", "DELETE"]), payload: z.record(z.unknown()), payloadDigest: z.string().regex(/^[a-f0-9]{64}$/), originInstallationId: z.string().uuid(), createdAt: z.string().datetime() }).strict()).max(500) }).strict();

export const backupCreateSchema = z.object({ encrypted: z.boolean().default(true) }).strict();
export const backupRestoreSchema = z.object({ backupId: z.string().uuid(), confirmation: z.literal("STAGE_VERIFIED_RESTORE_ON_RESTART") }).strict();
export const integrationExportSchema = z.object({ organizationId: z.string().uuid(), scanId: z.string().uuid(), format: z.enum(["SARIF", "JUNIT", "BURP_XML", "JSON"]) }).strict();

export const thirdPartyModuleManifestSchema = z.object({
  schemaVersion: z.literal(1),
  moduleId: z.string().regex(/^[a-z][a-z0-9-]{2,79}$/),
  version: z.string().regex(/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/),
  entrypoint: z.string().regex(/^[a-zA-Z0-9_./-]+\.m?js$/).refine((value) => !value.includes("..") && !value.startsWith("/")),
  description: z.string().min(1).max(500),
  permissions: z.object({ network: z.literal(false), childProcess: z.literal(false), filesystem: z.enum(["NONE", "PACKAGE_READ_ONLY"]), maxRuntimeMs: z.number().int().min(100).max(30000), maxMemoryMb: z.number().int().min(16).max(256) }).strict(),
  inputSchema: z.record(z.unknown()).default({}),
  outputLimit: z.number().int().min(1).max(1000).default(100)
}).strict();
export const thirdPartyModuleRegisterSchema = z.object({ organizationId: z.string().uuid(), packageDirectory: z.string().min(1).max(2000) }).strict();
export const thirdPartyModuleExecuteSchema = z.object({ input: z.record(z.unknown()) }).strict();
export const remoteWorkerStateSchema = z.object({ status: z.enum(["ONLINE", "DRAINING", "QUARANTINED", "REVOKED"]) }).strict();

export type ThirdPartyModuleManifest = z.infer<typeof thirdPartyModuleManifestSchema>;
