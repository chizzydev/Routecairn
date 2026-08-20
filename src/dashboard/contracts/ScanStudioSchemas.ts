import { z } from "zod";
import { authProfileSchema } from "../../core/auth/AuthProfile.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { objectPairInputSchema } from "../../modules/objectPairTesting/ObjectPairPlanner.js";
import { fieldExposureInputSchema } from "../../modules/fieldExposureTesting/FieldExposurePlanner.js";
import { authorizationMatrixInputSchema } from "../../modules/authorizationMatrix/AuthorizationMatrixPlanner.js";
import { equivalentRouteInputSchema } from "../../modules/equivalentRouteTesting/EquivalentRoutePlanner.js";
import { collectionAuthorizationInputSchema } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { bulkAuthorizationInputSchema } from "../../modules/bulkAuthorization/BulkAuthorizationPlanner.js";
import { fileAuthorizationInputSchema } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";

export const scanStudioAuthorizationSchema = z.object({
  category: z.enum(["OWNED", "CLIENT_AUTHORIZED", "BUG_BOUNTY", "CONTROLLED_LAB", "OTHER_AUTHORIZED"]),
  confirmed: z.literal(true),
  note: z.string().max(1000).optional()
}).strict();

const savedActorSchema = z.object({ source: z.literal("saved"), credentialProfileId: z.string().uuid() }).strict();
const ephemeralActorSchema = z.object({ source: z.literal("ephemeral"), profile: authProfileSchema }).strict();
export const scanStudioAuthActorSchema = z.discriminatedUnion("source", [savedActorSchema, ephemeralActorSchema]);

export const scanStudioAuthenticationSchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("public") }).strict(),
  z.object({ mode: z.literal("primary"), primary: scanStudioAuthActorSchema }).strict(),
  z.object({ mode: z.literal("account-pair"), accountA: scanStudioAuthActorSchema, accountB: scanStudioAuthActorSchema }).strict()
]).superRefine((value, ctx) => {
  if (value.mode === "account-pair" && value.accountA.source === "saved" && value.accountB.source === "saved" && value.accountA.credentialProfileId === value.accountB.credentialProfileId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["accountB"], message: "Account A and Account B must use different credential profiles." });
  }
});

export const scanStudioOutputSchema = z.object({
  json: z.literal(true).default(true),
  markdown: z.literal(true).default(true),
  html: z.literal(true).default(true)
}).strict();

const workflowEnvelopeShape = {
  enabled: z.boolean().default(true),
  editorMode: z.enum(["guided", "advanced"]).default("guided"),
  disabledCaseIds: z.array(z.string().min(1).max(120)).max(100).default([])
};

export const authorizationWorkflowConfigurationSchema = z.discriminatedUnion("workflowId", [
  z.object({ workflowId: z.literal("object-pair"), ...workflowEnvelopeShape, config: objectPairInputSchema }).strict(),
  z.object({ workflowId: z.literal("field-exposure"), ...workflowEnvelopeShape, config: fieldExposureInputSchema }).strict(),
  z.object({ workflowId: z.literal("authorization-matrix"), ...workflowEnvelopeShape, config: authorizationMatrixInputSchema }).strict(),
  z.object({ workflowId: z.literal("equivalent-route"), ...workflowEnvelopeShape, config: equivalentRouteInputSchema }).strict(),
  z.object({ workflowId: z.literal("collection-authorization"), ...workflowEnvelopeShape, config: collectionAuthorizationInputSchema }).strict(),
  z.object({ workflowId: z.literal("bulk-authorization"), ...workflowEnvelopeShape, config: bulkAuthorizationInputSchema }).strict(),
  z.object({ workflowId: z.literal("file-authorization"), ...workflowEnvelopeShape, config: fileAuthorizationInputSchema }).strict()
]);

export const authorizationWorkflowConfigurationsSchema = z.array(authorizationWorkflowConfigurationSchema).max(7).superRefine((workflows, ctx) => {
  const seen = new Set<string>();
  workflows.forEach((workflow, index) => {
    if (seen.has(workflow.workflowId)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [index, "workflowId"], message: `Duplicate workflow ${workflow.workflowId}.` });
    seen.add(workflow.workflowId);
  });
});

export const scanStudioSchema = z.object({
  version: z.literal(1),
  scanName: z.string().min(1).max(160),
  operatorNote: z.string().max(1000).optional(),
  authorization: scanStudioAuthorizationSchema,
  scope: scopeSchema,
  authentication: scanStudioAuthenticationSchema.default({ mode: "public" }),
  evidenceLevel: z.enum(["minimal", "normal", "strong"]).optional(),
  outputs: scanStudioOutputSchema.default({ json: true, markdown: true, html: true }),
  workflows: authorizationWorkflowConfigurationsSchema.default([]),
  workflowSummary: z.array(z.object({ type: z.string().min(1).max(80), caseCount: z.number().int().min(0).max(1000), valid: z.boolean() }).strict()).max(7).default([]),
  retestContext: z.object({
    findingId: z.string().uuid(),
    sourceOccurrenceId: z.string().uuid(),
    sourceScanId: z.string().uuid(),
    relevantModule: z.string().min(1).max(160),
    relevantWorkflow: z.string().min(1).max(80).optional(),
    relevantCase: z.string().min(1).max(160).optional(),
    purpose: z.string().min(1).max(240)
  }).strict().optional(),
  previewIdentity: z.string().regex(/^[a-f0-9]{64}$/).optional()
}).strict();

export type ScanStudioAuthentication = z.infer<typeof scanStudioAuthenticationSchema>;
export type ScanStudioAuthActor = z.infer<typeof scanStudioAuthActorSchema>;
export type AuthorizationWorkflowConfiguration = z.infer<typeof authorizationWorkflowConfigurationSchema>;
export type ScanStudioData = z.infer<typeof scanStudioSchema>;
