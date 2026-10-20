import { z } from "zod";
export const schemaImportSchema = z
  .object({ targetId: z.string().uuid(), document: z.string().min(1).max(262144) })
  .strict();
export const schemaSelectionSchema = z
  .object({
    revisionId: z.string().uuid(),
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    selections: z
      .array(
        z
          .object({
            routeId: z.string().max(80),
            candidateId: z.string().max(80),
            slots: z.record(
              z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,39}$/),
              z
                .string()
                .regex(/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,79}$/)
                .refine((v) => v !== "." && v !== "..")
            )
          })
          .strict()
      )
      .min(1)
      .max(8)
  })
  .strict();
export const mapComparisonSchema = z
  .object({ baselineRevisionId: z.string().uuid(), currentRevisionId: z.string().uuid() })
  .strict();
