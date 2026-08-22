import { z } from "zod";
import { productionMutationCaseSchema } from "./ProductionMutationCaseSchemas.js";
export const productionMutationApprovalSchema = z.object({ case: productionMutationCaseSchema, authorizationDeclaration: z.string().min(40).max(1200), confirmation: z.literal("I_CONFIRM_PRODUCTION_CONTROLLED_MUTATION_AND_CLEANUP_DUTY") }).strict();
export type ProductionMutationApprovalInput = z.infer<typeof productionMutationApprovalSchema>;
