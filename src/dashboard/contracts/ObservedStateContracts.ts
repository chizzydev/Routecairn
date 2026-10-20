import { z } from "zod";
const fingerprint = z.string().regex(/^[a-f0-9]{64}$/);
export const observedStateDraftSchema = z
  .object({
    name: z.string().trim().min(4).max(100),
    purpose: z.string().trim().min(10).max(240),
    matrixRevisionId: z.string().uuid(),
    supersedes: z.string().uuid().optional(),
    maximumObservationAgeMinutes: z.number().int().min(1).max(10080),
    revisionPaths: z
      .array(z.object({ routeId: z.string().min(1).max(80), path: z.string().min(1).max(80) }).strict())
      .min(2)
      .max(4)
  })
  .strict();
export const observedStateDecisionSchema = z.discriminatedUnion("action", [
  z
    .object({
      action: z.literal("APPROVE"),
      digest: fingerprint,
      authorityConfirmed: z.literal(true),
      expectationsConfirmed: z.literal(true),
      scopeConfirmation: z.literal("OBSERVATIONS_ONLY_TRANSITION_AUTHORIZATION_NOT_TESTED")
    })
    .strict(),
  z.object({ action: z.literal("REVOKE"), digest: fingerprint, reason: z.string().trim().min(10).max(240) }).strict()
]);
export type ObservedStateDraft = z.infer<typeof observedStateDraftSchema>;
export type ObservedStateDecision = z.infer<typeof observedStateDecisionSchema>;
export type ObservedStateOutcome = "MATCHED" | "DRIFT" | "INCONCLUSIVE";
