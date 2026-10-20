import { identityModelSchema } from "../../core/auth/IdentityModel.js";
import { applicationObservationFieldSchema } from "./ApplicationMappingContracts.js";
import { z } from "zod";
const path = z
  .string()
  .min(1)
  .max(300)
  .regex(/^\/[A-Za-z0-9_./-]*$/)
  .refine(
    (p) => !p.includes("//") && !p.split("/").some((v) => v === "." || v === ".."),
    "Literal read-only path required"
  );
const field = applicationObservationFieldSchema;
const actor = z
  .object({
    principal: z.string().min(1).max(100),
    tenant: z.string().min(1).max(100).optional(),
    role: z.string().min(1).max(100),
    authorizationHeader: z
      .string()
      .min(1)
      .max(4000)
      .refine((s) => !/[\r\n\x00]/.test(s)),
    expiresAt: z
      .string()
      .datetime()
      .refine((s) => Date.parse(s) > Date.now())
  })
  .strict();
export const applicationOnboardingSchema = z
  .object({
    identityModel: identityModelSchema.optional(),
    displayName: z.string().min(1).max(160),
    origin: z
      .string()
      .url()
      .max(300)
      .refine((s) => {
        try {
          const u = new URL(s);
          return u.hostname === "127.0.0.1" && ["http:", "https:"].includes(u.protocol) && s === u.origin;
        } catch {
          return false;
        }
      }, "Exact owned 127.0.0.1 origin required"),
    authorizationSummary: z.string().min(12).max(1000),
    identityPath: path,
    principalField: field,
    tenantField: field.optional(),
    roleField: field,
    seedPath: path,
    objectField: field,
    objectTenantField: field.optional(),
    actors: z.object({ primary: actor, account_a: actor, account_b: actor }).strict(),
    ownedReadOnlyConfirmed: z.literal(true)
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.identityModel && v.principalField === v.roleField)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Principal and role must have distinct native field mappings."
      });
    if (v.identityModel === "PRINCIPAL_ROLE") {
      if (
        v.tenantField !== undefined ||
        v.objectTenantField !== undefined ||
        Object.values(v.actors).some((a) => a.tenant !== undefined)
      )
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Principal-role mode forbids tenant fields and metadata."
        });
    } else if (!v.tenantField || !v.objectTenantField || Object.values(v.actors).some((a) => !a.tenant))
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Tenant-aware onboarding requires all tenant fields and actors."
      });
  })
  .refine(
    (v) => new Set(Object.values(v.actors).map((a) => a.principal)).size === 3,
    "Three distinct declared principals required"
  );
export type ApplicationOnboardingInput = z.infer<typeof applicationOnboardingSchema>;
