import { z } from "zod";
export const identityModelSchema = z.enum(["TENANT_AWARE", "PRINCIPAL_ROLE"]);
export type IdentityModel = z.infer<typeof identityModelSchema>;
/** Missing mode on historical application records retains their tenant-aware meaning. */
export function applicationIdentityModel(value: unknown): IdentityModel {
  return value === undefined ? "TENANT_AWARE" : identityModelSchema.parse(value);
}
