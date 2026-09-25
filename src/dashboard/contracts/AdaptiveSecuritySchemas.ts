import { z } from "zod";
import { liveAcceptanceLaneKindSchema } from "./LiveAcceptanceSchemas.js";

export const adaptivePolicyInputSchema = z.object({
  targetId: z.string().uuid(),
  requiredLanes: z.array(liveAcceptanceLaneKindSchema.exclude(["CUSTOM"])).min(1).max(24),
  requireEvidenceForNotApplicable: z.boolean().default(true),
  detectRemovedSurfaces: z.boolean().default(true),
  confirmation: z.literal("I_CONFIRM_TARGET_SECURITY_MODEL_POLICY")
}).strict().superRefine((value, ctx) => {
  if (new Set(value.requiredLanes).size !== value.requiredLanes.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredLanes"], message: "Required lane kinds must be unique." });
});

export const adaptiveAnalyzeSchema = z.object({ targetId: z.string().uuid(), scanId: z.string().uuid() }).strict();
export const adaptiveBaselineSchema = z.object({ modelDigest: z.string().regex(/^[a-f0-9]{64}$/), confirmation: z.literal("I_CONFIRM_EXPECTED_SECURITY_MODEL_BASELINE") }).strict();
export const adaptiveRecommendationDecisionSchema = z.object({
  decision: z.enum(["APPROVED", "DISMISSED"]),
  rationale: z.string().min(12).max(1000),
  confirmation: z.literal("I_CONFIRM_ADAPTIVE_RECOMMENDATION_DECISION")
}).strict();
export const adaptiveRecommendationLinkSchema = z.object({ scanId: z.string().uuid(), caseFingerprint: z.string().regex(/^[a-f0-9]{64}$/), confirmation: z.literal("I_CONFIRM_LINK_EXACT_RECOMMENDATION_EXECUTION") }).strict();

export const adaptiveExecutionBindingSchema = z.object({
  recommendationId: z.string().uuid(),
  sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  executionFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  compilerVersion: z.union([z.literal(1), z.literal(2)])
}).strict();

export type AdaptivePolicyInput = z.infer<typeof adaptivePolicyInputSchema>;
export type AdaptiveExecutionBinding = z.infer<typeof adaptiveExecutionBindingSchema>;
