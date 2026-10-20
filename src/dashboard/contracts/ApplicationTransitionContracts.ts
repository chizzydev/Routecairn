import { z } from "zod";
const scalar = z.union([z.string().min(1).max(256), z.number().finite()]);
const path = z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/);
const actor = z.enum(["primary", "account-a", "account-b"]);
export const transitionEventSchema = z
  .object({
    eventId: z.string().uuid(),
    targetOrigin: z.string().url().max(200),
    routeId: path,
    actorId: actor,
    principalId: z.string().min(1).max(100),
    actorTenantId: z.string().min(1).max(100),
    role: z.string().min(1).max(100),
    resourceValue: scalar,
    tenantValue: scalar,
    statePath: path,
    beforeState: scalar,
    afterState: scalar,
    revisionPath: path,
    fromRevision: z.number().int().nonnegative().safe(),
    toRevision: z.number().int().positive().safe(),
    occurredAt: z.string().datetime()
  })
  .strict();
export const transitionDeclarationSchema = z
  .object({
    beforeMapRevisionId: z.string().uuid(),
    policy: z.enum(["LEGITIMATE", "FORBIDDEN"]),
    purpose: z.string().min(10).max(240),
    authorityKeySha256: z.string().regex(/^[a-f0-9]{64}$/),
    publicKeySpki: z
      .string()
      .regex(/^[A-Za-z0-9+/]{59}=$/)
      .max(60),
    signature: z
      .string()
      .regex(/^[A-Za-z0-9+/]{86}==$/)
      .max(88),
    event: transitionEventSchema
  })
  .strict();
export const transitionReviewSchema = z
  .object({
    authorityConfirmed: z.literal(true),
    authorityKeySha256: z.string().regex(/^[a-f0-9]{64}$/),
    checks: z
      .array(
        z
          .object({
            routeId: path,
            actorId: z.enum(["primary", "account-a", "account-b", "anonymous"]),
            purpose: z.string().min(10).max(240),
            consent: z.literal(true)
          })
          .strict()
      )
      .min(8)
      .max(16)
  })
  .strict();
export type TransitionDeclaration = z.infer<typeof transitionDeclarationSchema>;
export type TransitionReview = z.infer<typeof transitionReviewSchema>;
