import { z } from "zod";

export const controlledMutationApprovalSchema = z.object({
  caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120),
  targetId: z.string().uuid(),
  targetOrigin: z.string().url(),
  planIdentity: z.string().regex(/^[a-f0-9]{64}$/),
  authorizationDeclaration: z.string().min(20).max(1000),
  expiresAt: z.string().datetime(),
  confirmation: z.literal("I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY")
}).strict();

export type ControlledMutationApprovalInput = z.infer<typeof controlledMutationApprovalSchema>;
