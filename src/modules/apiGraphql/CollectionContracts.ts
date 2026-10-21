import { z } from "zod";
export const COLLECTION_ALGORITHM = "bounded-native-collection-v1" as const;
const path = z
  .string()
  .min(1)
  .max(80)
  .regex(/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){0,7}$/)
  .refine(
    (v) => !/(?:__proto__|prototype|constructor|password|token|secret|cookie|authorization|session|key)/i.test(v),
    "Non-secret own-property paths required"
  );
export const collectionContractSchema = z
  .object({
    kind: z.literal("COLLECTION"),
    algorithm: z.literal(COLLECTION_ALGORITHM),
    collectionPath: path,
    itemIdentityPath: path,
    ownerPath: path,
    ownerRule: z.literal("EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING"),
    maxItems: z.number().int().min(1).max(64),
    maxResponseBytes: z.number().int().min(512).max(65536),
    coverage: z.enum(["THIS_RESPONSE_ONLY", "UNPAGINATED_RESPONSE"]),
    pagination: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("OWNER_DECLARED_UNPAGINATED"), ownerConfirmed: z.literal(true) }).strict(),
      z.object({ kind: z.literal("HAS_MORE_BOOLEAN"), path }).strict(),
      z.object({ kind: z.literal("NEXT_CURSOR"), path }).strict()
    ])
  })
  .strict()
  .superRefine((v, c) => {
    if (v.itemIdentityPath === v.ownerPath)
      c.addIssue({ code: z.ZodIssueCode.custom, message: "Entry identity must be distinct from ownership" });
    if (v.coverage === "UNPAGINATED_RESPONSE" && v.pagination.kind !== "OWNER_DECLARED_UNPAGINATED")
      c.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Whole collection requires explicit unpaginated declaration"
      });
  });
export type CollectionContract = z.infer<typeof collectionContractSchema>;
export const routeObservationSchema = z
  .discriminatedUnion("kind", [z.object({ kind: z.literal("SCALAR") }).strict(), collectionContractSchema.innerType()])
  .superRefine((v, c) => {
    if (v.kind === "COLLECTION") {
      const p = collectionContractSchema.safeParse(v);
      if (!p.success) for (const issue of p.error.issues) c.addIssue(issue);
    }
  });
