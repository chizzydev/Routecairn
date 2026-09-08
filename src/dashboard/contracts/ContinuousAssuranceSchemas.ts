import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);

export const continuousAssurancePolicyInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  name: z.string().min(3).max(160),
  description: z.string().max(2000).default(""),
  targetId: z.string().uuid(),
  authorization: z.object({
    proofReference: z.string().min(3).max(500),
    proofDigest: digest,
    validFrom: z.string().datetime(),
    expiresAt: z.string().datetime()
  }).strict(),
  triggers: z.object({
    scheduleEnabled: z.boolean(),
    intervalMinutes: z.number().int().min(15).max(525_600),
    deploymentEnabled: z.boolean(),
    quietWhenHealthy: z.literal(true)
  }).strict(),
  adapterProfileIds: z.array(z.string().uuid()).min(1).max(20),
  baselines: z.array(z.object({ adapterProfileId: z.string().uuid(), scanId: z.string().uuid() }).strict()).max(20).default([]),
  requiredCases: z.array(z.object({
    adapterProfileId: z.string().uuid(),
    workflowId: z.string().min(1).max(100),
    caseFingerprint: digest
  }).strict()).min(1).max(200),
  gates: z.object({
    failOnRegression: z.literal(true),
    failOnNewFinding: z.boolean().default(true),
    failOnOpenDrift: z.boolean().default(true),
    requireExactCases: z.literal(true),
    requireCleanupResolved: z.literal(true)
  }).strict(),
  evidence: z.object({
    retentionDays: z.number().int().min(1).max(3650),
    autoExportOn: z.array(z.enum(["REGRESSION", "FAILED", "CLEANUP_REQUIRED", "APPROVAL_REQUIRED"])).max(4),
    preserveFailures: z.literal(true),
    preserveCleanupEvidence: z.literal(true)
  }).strict()
}).strict().superRefine((value, ctx) => {
  if (new Set(value.adapterProfileIds).size !== value.adapterProfileIds.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["adapterProfileIds"], message: "Adapter profiles must be unique." });
  if (new Set(value.baselines.map((item) => item.adapterProfileId)).size !== value.baselines.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["baselines"], message: "Each adapter can have only one baseline." });
  if (value.baselines.some((item) => !value.adapterProfileIds.includes(item.adapterProfileId))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["baselines"], message: "Every baseline must belong to a selected adapter." });
  const caseKeys = value.requiredCases.map((item) => `${item.adapterProfileId}\0${item.workflowId}\0${item.caseFingerprint}`);
  if (new Set(caseKeys).size !== caseKeys.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredCases"], message: "Required exact cases must be unique." });
  if (value.requiredCases.some((item) => !value.adapterProfileIds.includes(item.adapterProfileId))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredCases"], message: "Every required case must belong to a selected adapter." });
  if (value.adapterProfileIds.some((id) => !value.requiredCases.some((item) => item.adapterProfileId === id))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredCases"], message: "Every selected adapter requires at least one exact baseline case." });
  if (Date.parse(value.authorization.validFrom) >= Date.parse(value.authorization.expiresAt)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authorization", "expiresAt"], message: "Authorization expiry must follow its validity start." });
  if (!value.triggers.scheduleEnabled && !value.triggers.deploymentEnabled) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["triggers"], message: "Enable at least one continuous-assurance trigger." });
  if (new Set(value.evidence.autoExportOn).size !== value.evidence.autoExportOn.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["evidence", "autoExportOn"], message: "Evidence export triggers must be unique." });
});

export const continuousAssuranceReviewSchema = z.object({
  versionId: z.string().uuid(),
  policyDigest: digest,
  confirmation: z.literal("I_CONFIRM_CONTINUOUS_ASSURANCE_POLICY")
}).strict();

export const continuousAssuranceStateSchema = z.object({
  enabled: z.boolean(),
  impactDigest: digest,
  confirmation: z.literal("I_CONFIRM_CONTINUOUS_ASSURANCE_STATE_CHANGE")
}).strict();

export const continuousAssuranceRunSchema = z.object({
  confirmation: z.literal("I_CONFIRM_CONTINUOUS_ASSURANCE_RUN")
}).strict();

export const continuousAssuranceTokenRotationSchema = z.object({
  confirmation: z.literal("I_CONFIRM_CONTINUOUS_ASSURANCE_TOKEN_ROTATION")
}).strict();

export const continuousAssuranceNotificationAckSchema = z.object({
  confirmation: z.literal("I_ACKNOWLEDGE_CONTINUOUS_ASSURANCE_NOTIFICATION")
}).strict();

export const deploymentTriggerSchema = z.object({
  policyId: z.string().uuid(),
  deploymentId: z.string().min(1).max(200).regex(/^[A-Za-z0-9._:/@+-]+$/),
  buildFingerprint: digest
}).strict();

export const evidenceGovernancePolicySchema = z.object({
  retentionDays: z.number().int().min(1).max(3650),
  preserveFailedScans: z.literal(true),
  preserveUnresolvedCleanup: z.literal(true),
  preserveUnreviewedFindings: z.literal(true),
  maximumExportBytes: z.number().int().min(1024).max(250 * 1024 * 1024),
  expectedVersion: z.number().int().positive(),
  confirmation: z.literal("I_CONFIRM_EVIDENCE_GOVERNANCE_POLICY")
}).strict();

export const evidenceExportSchema = z.object({
  scanIds: z.array(z.string().uuid()).min(1).max(25),
  confirmation: z.literal("I_CONFIRM_ENCRYPTED_EVIDENCE_EXPORT")
}).strict();

export const evidencePurgeSchema = z.object({
  previewDigest: digest,
  confirmation: z.literal("I_CONFIRM_EVIDENCE_PURGE")
}).strict();

export type ContinuousAssurancePolicyInput = z.infer<typeof continuousAssurancePolicyInputSchema>;
export type DeploymentTrigger = z.infer<typeof deploymentTriggerSchema>;
export type EvidenceGovernancePolicy = Omit<z.infer<typeof evidenceGovernancePolicySchema>, "confirmation" | "expectedVersion">;
