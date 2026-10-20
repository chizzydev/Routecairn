import { reviewedWorkflowSchema } from "./BusinessRelationshipContracts.js";
import { authorizationWorkbenchInputSchema } from "./AuthorizationWorkbenchContracts.js";
import { z } from "zod";
import { transitionDeclarationSchema, transitionReviewSchema } from "./ApplicationTransitionContracts.js";
const fp = z.string().regex(/^[a-f0-9]{64}$/);
export const hypothesisGenerateSchema = z
  .object({
    mapRevisionId: z.string().uuid(),
    supersedes: z.string().uuid().optional(),
    transition: transitionDeclarationSchema.optional(),
    workflow: reviewedWorkflowSchema.optional()
  })
  .strict();
export const hypothesisDecisionSchema = z.discriminatedUnion("action", [
  z
    .object({
      action: z.literal("REVIEW_FLOW"),
      digest: fp,
      candidateId: fp,
      policyConfirmed: z.literal(true),
      ownershipConfirmed: z.literal(true),
      relationshipExplanation: z.string().min(10).max(240),
      transitionReview: transitionReviewSchema.optional(),
      expectations: authorizationWorkbenchInputSchema.shape.expectations
    })
    .strict(),
  z
    .object({
      action: z.literal("REJECT"),
      digest: fp,
      candidateId: fp,
      reason: z.enum(["EXPECTED_SHARED_ACCESS", "NOT_A_SECURITY_BOUNDARY", "INSUFFICIENT_CONTEXT"])
    })
    .strict(),
  z
    .object({
      action: z.literal("REVIEW"),
      digest: fp,
      candidateId: fp,
      policyConfirmed: z.literal(true),
      ownershipConfirmed: z.literal(true),
      explanation: z.string().min(10).max(240),
      decisions: z
        .object({
          primary: z.literal("ALLOW"),
          "account-a": z.enum(["ALLOW", "DENY"]),
          "account-b": z.enum(["ALLOW", "DENY"]),
          anonymous: z.enum(["ALLOW", "DENY"])
        })
        .strict(),
      identity: z.union([z.string().min(1).max(256), z.number().finite()]),
      tenant: z.union([z.string().min(1).max(256), z.number().finite()]).optional()
    })
    .strict()
]);
