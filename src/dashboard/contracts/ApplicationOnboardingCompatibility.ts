import { identityModelSchema } from "../../core/auth/IdentityModel.js";
import { z } from "zod";

/** Offline declarations only; deliberately accepts neither credentials nor target URLs. */
export const applicationOnboardingCompatibilitySchema = z
  .object({
    identityModel: identityModelSchema.optional(),
    tenantIdentity: z.enum(["PRESENT", "ABSENT", "UNKNOWN"]),
    actorProfiles: z.enum(["THREE_DISTINCT", "INSUFFICIENT", "UNKNOWN"]),
    getEffects: z.enum(["READ_ONLY", "WRITES", "UNKNOWN"]),
    runtimeIsolation: z.enum(["CONFIRMED", "UNCONFIRMED", "UNKNOWN"]),
    resourceShape: z.enum(["SCALAR_MARKERS", "COLLECTION_ONLY", "UNKNOWN"])
  })
  .strict();
export type ApplicationOnboardingCompatibilityInput = z.infer<typeof applicationOnboardingCompatibilitySchema>;
export const unknownOnboardingCompatibility: ApplicationOnboardingCompatibilityInput = {
  tenantIdentity: "UNKNOWN",
  actorProfiles: "UNKNOWN",
  getEffects: "UNKNOWN",
  runtimeIsolation: "UNKNOWN",
  resourceShape: "UNKNOWN"
};

/** Explains the existing guided-mapping contract. Never manufactures tenant or execution authority. */
export function assessApplicationOnboardingCompatibility(value: unknown) {
  const v = applicationOnboardingCompatibilitySchema.parse(value);
  const blockers: Array<{ code: string; message: string }> = [];
  if (v.tenantIdentity === "ABSENT" && v.identityModel !== "PRINCIPAL_ROLE")
    blockers.push({
      code: "TENANTLESS_MAPPING_UNSUPPORTED",
      message:
        "Current guided mapping requires a genuine verified tenant identity. Do not substitute user IDs, roles or invented tenants. Choose explicit PRINCIPAL_ROLE mode for tenantless verification; tenant-aware requirements otherwise remain in force."
    });
  if (v.actorProfiles === "INSUFFICIENT")
    blockers.push({
      code: "THREE_REAL_ACTORS_REQUIRED",
      message:
        "Provide three distinct legitimate target-bound actor profiles. Different roles alone do not establish distinct principals."
    });
  if (v.getEffects === "WRITES")
    blockers.push({
      code: "GET_SIDE_EFFECT_REVIEW_REQUIRED",
      message:
        "GET middleware or handlers write state. Do not confirm read-only observations; isolate and review these effects with the owner before any execution."
    });
  if (v.runtimeIsolation === "UNCONFIRMED")
    blockers.push({
      code: "RUNTIME_ISOLATION_REQUIRED",
      message:
        "Establish a separately owned local database, process environment and outbound-service isolation. A localhost URL alone does not isolate background jobs or production dependencies."
    });
  if (v.resourceShape === "COLLECTION_ONLY")
    blockers.push({
      code: "SCALAR_OWNERSHIP_EVIDENCE_REQUIRED",
      message:
        "Current guided observations use scalar JSON markers. Collection membership or a successful /me response alone cannot prove foreign-object denial. Do not invent an object GET endpoint."
    });
  const unknown = Object.entries(v)
    .filter(([, entry]) => entry === "UNKNOWN")
    .map(([key]) => key);
  return {
    status: blockers.length
      ? ("BLOCKED" as const)
      : unknown.length
        ? ("INCOMPLETE" as const)
        : ("DECLARED_COMPATIBLE_REVIEW_REQUIRED" as const),
    blockers,
    unknown,
    executionAuthority: "NONE" as const,
    requestsSent: 0 as const,
    credentialDecryption: false as const,
    nativeVerified: false as const,
    notice:
      "Source declarations are advisory, not saved authorization, native proof or a security verdict. Server validation and separate execution approval remain mandatory."
  };
}
