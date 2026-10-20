import { collectionContractSchema } from "../../modules/apiGraphql/CollectionOwnership.js";
import { z } from "zod";
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/);
const scalar = z.union([z.string().min(1).max(256), z.number().finite()]);
export const authorizationWorkbenchInputSchema = z
  .object({
    targetId: z.string().uuid(),
    sourceScanId: z.string().uuid(),
    mappingAcquisitionId: z.string().uuid().optional(),
    hypothesisReviewId: z.string().uuid().optional(),
    credentials: z
      .object({
        primary: z.string().uuid().optional(),
        account_a: z.string().uuid().optional(),
        account_b: z.string().uuid().optional()
      })
      .strict(),
    expectations: z
      .array(
        z
          .object({
            routeId: id,
            url: z
              .string()
              .url()
              .max(1000)
              .refine((v) => {
                const u = new URL(v);
                return ["http:", "https:"].includes(u.protocol) && !u.username && !u.password && !u.search && !u.hash;
              }, "An HTTP URL without credentials, query or fragment is required")
              .optional(),
            kind: z.enum(["OBJECT_AUTHORIZATION", "TENANT_ISOLATION", "FUNCTION_AUTHORIZATION"]),
            explanation: z.string().min(10).max(240),
            decisions: z.record(id, z.enum(["ALLOW", "DENY", "UNKNOWN"])),
            collection: collectionContractSchema.optional(),
            identity: z.object({ path: id, expectedValue: scalar }).strict().optional(),
            tenant: z.object({ path: id, expectedValue: scalar }).strict().optional(),
            states: z
              .array(z.object({ path: id, expectedValue: scalar }).strict())
              .min(1)
              .max(2)
              .optional(),
            dependsOn: z.array(id).max(3).optional()
          })
          .strict()
      )
      .min(1)
      .max(8)
  })
  .strict();
export type AuthorizationWorkbenchInput = z.infer<typeof authorizationWorkbenchInputSchema>;
export const authorizationWorkbenchExecuteSchema = z
  .object({
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    confirmation: z.literal("I_AUTHORIZE_THE_EXACT_READ_ONLY_FIXTURE_CHECKS")
  })
  .strict();
