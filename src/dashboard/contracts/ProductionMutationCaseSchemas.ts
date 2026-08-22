import { z } from "zod";

const pathSchema = z.string().min(1).max(1000).regex(/^\/(?!\/)/, "Endpoint must be a same-origin relative path").refine((value) => !value.includes("#") && !value.includes(".."), "Endpoint path cannot contain fragments or traversal");
const assertionSchema = z.object({ path: z.string().min(1).regex(/^[A-Za-z0-9_.-]+$/), operator: z.enum(["EQUALS", "NOT_EQUALS", "PRESENT", "ABSENT"]), expectedValue: z.unknown().optional() }).strict();
const verificationSchema = z.object({ method: z.literal("GET"), path: pathSchema, assertions: z.array(assertionSchema).min(1).max(20), attempts: z.number().int().min(1).max(10).default(3), delayMs: z.number().int().min(0).max(30000).default(250) }).strict();
const mutationSchema = z.object({ method: z.enum(["POST", "PATCH", "PUT"]), path: pathSchema, body: z.record(z.unknown()) }).strict();

export const productionMutationCaseSchema = z.object({
  schemaVersion: z.literal(1), caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120), targetId: z.string().uuid(), environment: z.literal("PRODUCTION"), productionAcknowledged: z.literal(true), actorCredentialProfileId: z.string().uuid(), disposableTargetAlias: z.string().min(1).max(160), authorityField: z.string().min(1).regex(/^[A-Za-z0-9_.-]+$/), mutationValue: z.unknown(), allowedValues: z.array(z.unknown()).min(1).max(20), identity: verificationSchema, precondition: verificationSchema, mutation: mutationSchema, impactVerification: verificationSchema, protectedAction: verificationSchema.optional(), rollback: mutationSchema, restorationVerification: verificationSchema, authorizationExpiresAt: z.string().datetime()
}).strict().superRefine((value, ctx) => {
  if (!value.allowedValues.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value.mutationValue))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["mutationValue"], message: "Mutation value must be explicitly allowlisted" });
  const mutationKeys = Object.keys(value.mutation.body);
  if (mutationKeys.length !== 1 || mutationKeys[0] !== value.authorityField || JSON.stringify(value.mutation.body[value.authorityField]) !== JSON.stringify(value.mutationValue)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["mutation", "body"], message: "Mutation body must contain exactly the configured authority field and value" });
  const rollbackKeys = Object.keys(value.rollback.body);
  if (rollbackKeys.length !== 1 || rollbackKeys[0] !== value.authorityField) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["rollback", "body"], message: "Rollback body must restore exactly the configured authority field" });
});

export type ProductionMutationCase = z.infer<typeof productionMutationCaseSchema>;
