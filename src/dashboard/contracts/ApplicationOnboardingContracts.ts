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
    tenant: z.string().min(1).max(100),
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
    tenantField: field,
    roleField: field,
    seedPath: path,
    objectField: field,
    objectTenantField: field,
    actors: z.object({ primary: actor, account_a: actor, account_b: actor }).strict(),
    ownedReadOnlyConfirmed: z.literal(true)
  })
  .strict()
  .refine(
    (v) => new Set(Object.values(v.actors).map((a) => a.principal)).size === 3,
    "Three distinct declared principals required"
  );
export type ApplicationOnboardingInput = z.infer<typeof applicationOnboardingSchema>;
