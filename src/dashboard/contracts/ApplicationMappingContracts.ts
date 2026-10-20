import { routeObservationSchema } from "../../modules/apiGraphql/CollectionOwnership.js";
import { identityModelSchema } from "../../core/auth/IdentityModel.js";
import { discoveryBindingSchema } from "./ApplicationDiscoveryContracts.js";
import { schemaSelectionSchema } from "./ApplicationSchemaContracts.js";
import { z } from "zod";
import { authorizationWorkbenchInputSchema } from "./AuthorizationWorkbenchContracts.js";
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/);
export const applicationObservationFieldSchema = z
  .string()
  .min(1)
  .max(80)
  .regex(/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){0,7}$/)
  .refine(
    (v) => !/(?:__proto__|prototype|constructor|password|token|secret|cookie|authorization|session|key)/i.test(v),
    "Only non-secret identity field paths are permitted"
  );
const path = applicationObservationFieldSchema;
export const applicationMappingFieldsSchema = z
  .object({
    intakeBinding: z
      .object({ revisionId: z.string().uuid(), digest: z.string().regex(/^[a-f0-9]{64}$/) })
      .strict()
      .optional(),
    schemaBinding: schemaSelectionSchema.optional(),
    discoveryBinding: discoveryBindingSchema.optional(),
    identityModel: identityModelSchema.optional(),
    targetId: z.string().uuid(),
    credentials: z
      .object({ primary: z.string().uuid(), account_a: z.string().uuid(), account_b: z.string().uuid() })
      .strict(),
    routes: z
      .array(
        z
          .object({
            id,
            kind: z.enum(["OBJECT", "FUNCTION"]),
            url: z.string().url().max(1000),
            pathTemplate: z.string().min(1).max(200),
            method: z.literal("GET"),
            identityPath: path,
            observation: routeObservationSchema.optional(),
            tenantPath: path.optional(),
            statePaths: z
              .array(path)
              .min(1)
              .max(2)
              .refine((v) => new Set(v).size === v.length, "Distinct state fields required")
              .optional()
          })
          .strict()
          .refine(
            (r) =>
              !(r.statePaths ?? []).some((p) => p === r.identityPath || p === r.tenantPath) &&
              (r.observation?.kind !== "COLLECTION" ||
                (r.kind === "OBJECT" &&
                  r.identityPath === r.observation.itemIdentityPath &&
                  !r.tenantPath &&
                  !r.statePaths)),
            "State fields must be separate from object/tenant markers"
          )
      )
      .min(1)
      .max(8),
    identityContextConfirmed: z.literal(true),
    readOnlyRoutesConfirmed: z.literal(true)
  })
  .strict();
export const applicationMappingInputSchema = applicationMappingFieldsSchema.superRefine((v, ctx) => {
  if (v.identityModel === "PRINCIPAL_ROLE" && v.routes.some((r) => r.tenantPath !== undefined))
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Principal-role observations cannot declare tenant fields." });
});
export type ApplicationMappingInput = z.infer<typeof applicationMappingInputSchema>;
export const applicationMappingExecuteSchema = z
  .object({
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    confirmation: z.literal("I_AUTHORIZE_THE_EXACT_READ_ONLY_OBSERVATIONS")
  })
  .strict();
export const applicationMappingPolicySchema = z
  .object({ expectations: authorizationWorkbenchInputSchema.shape.expectations, policyConfirmed: z.literal(true) })
  .strict();
