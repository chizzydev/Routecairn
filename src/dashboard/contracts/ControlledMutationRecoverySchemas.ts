import { z } from "zod";
export const controlledMutationRecoverySchema = z.object({ requestId: z.string().uuid().optional(), approvalId: z.string().uuid(), bundlePath: z.string().min(1).max(1000), caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120), targetId: z.string().uuid(), credentialProfileId: z.string().uuid() }).strict();
