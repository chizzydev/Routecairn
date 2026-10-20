import { z } from "zod";
import { applicationObservationFieldSchema } from "./ApplicationMappingContracts.js";
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/);
export const businessRelationshipSchema = z
  .object({
    name: z.string().trim().min(4).max(100),
    producer: id,
    consumer: id,
    identifier: applicationObservationFieldSchema,
    reference: applicationObservationFieldSchema,
    producerVersion: applicationObservationFieldSchema,
    consumerVersion: applicationObservationFieldSchema,
    ownership: z
      .object({
        path: applicationObservationFieldSchema,
        actorId: z.enum(["primary", "account-a", "account-b"]),
        principalId: z.string().trim().min(1).max(160),
        tenantId: z.string().trim().min(1).max(160)
      })
      .strict()
      .optional()
  })
  .strict()
  .refine(
    (e) => e.producer !== e.consumer && e.identifier !== e.producerVersion && e.reference !== e.consumerVersion,
    "Distinct operations and version fields required"
  );
export const reviewedWorkflowSchema = z
  .object({
    name: z.string().min(4).max(100),
    routeIds: z
      .array(id)
      .min(2)
      .max(4)
      .refine((v) => new Set(v).size === v.length, "Distinct ordered steps required"),
    relationships: z.array(businessRelationshipSchema).min(1).max(3).optional()
  })
  .strict()
  .superRefine((w, c) => {
    const seen = new Set<string>();
    for (const e of w.relationships ?? []) {
      const p = w.routeIds.indexOf(e.producer),
        q = w.routeIds.indexOf(e.consumer),
        key = e.producer + ":" + e.consumer;
      if (p < 0 || q < 0 || p >= q || seen.has(key))
        c.addIssue({ code: "custom", message: "Unique forward relationships must reference exact ordered operations" });
      seen.add(key);
    }
  });
export type BusinessRelationship = z.infer<typeof businessRelationshipSchema>;
export type ReviewedWorkflow = z.infer<typeof reviewedWorkflowSchema>;
export const triageNoteSchema = z
  .object({
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    disposition: z.enum(["INVESTIGATE", "NEEDS_OWNER_CONTEXT", "OWNER_EXPECTED_BEHAVIOR"]),
    rationale: z.string().trim().min(10).max(500),
    reviewConfirmed: z.literal(true)
  })
  .strict();
