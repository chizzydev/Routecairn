import { z } from "zod";
import { applicationMappingInputSchema } from "./ApplicationMappingContracts.js";
const fingerprint = z.string().regex(/^[a-f0-9]{64}$/);
export const ownedApplicationIntakeSchema = z
  .object({
    targetId: z.string().uuid(),
    credentials: applicationMappingInputSchema.shape.credentials,
    artifact: z
      .object({
        version: z.literal(1),
        kind: z.enum(["MINIMIZED_HAR", "OWNER_EVIDENCE_EXPORT"]),
        origin: z.string().url().max(300),
        exportSha256: fingerprint,
        capturedAt: z.string().datetime(),
        provenance: z.enum([
          "OWNER_LOCAL_APPLICATION",
          "SEPARATELY_MAINTAINED_TEST_APPLICATION",
          "SELF_MAINTAINED_FIXTURE"
        ]),
        actors: z
          .array(
            z
              .object({
                slot: z.enum(["primary", "account_a", "account_b"]),
                principalFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
                tenantFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
                roleFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
                sessionEvidenceSha256: fingerprint
              })
              .strict()
          )
          .length(3),
        routes: applicationMappingInputSchema.shape.routes
      })
      .strict(),
    ownerScopeConfirmed: z.literal(true),
    offlineOnlyConfirmed: z.literal(true)
  })
  .strict();
export type OwnedApplicationIntake = z.infer<typeof ownedApplicationIntakeSchema>;
