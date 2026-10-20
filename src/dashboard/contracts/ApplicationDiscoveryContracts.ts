import { z } from "zod";
const sha = z.string().regex(/^[a-f0-9]{64}$/);
export const discoveryProposalSchema = z
  .object({
    mapRevisionId: z.string().uuid(),
    allowedPathPrefixes: z
      .array(
        z
          .string()
          .regex(/^\/(?:[A-Za-z0-9._~-]+\/)*$/)
          .max(180)
      )
      .min(1)
      .max(16),
    maxRoutes: z.number().int().min(1).max(8),
    maxRequests: z.number().int().min(8).max(36),
    scopeConfirmed: z.literal(true)
  })
  .strict();
export const discoveryBindingSchema = z
  .object({
    proposalId: z.string().uuid(),
    digest: sha,
    selections: z
      .array(z.object({ routeId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/), candidateId: sha }).strict())
      .min(1)
      .max(8)
  })
  .strict();
